"""Prompt -> local model boundary for the Incident Analysis Agent.

This module is the orchestration seam between the deterministic forensic
pipeline (``IncidentSerializer`` -> ``IncidentAnalysisPromptBuilder``) and
the local Qwen model. It performs no reasoning of its own:

    IncidentSerializer
            v
    IncidentAnalysisPromptBuilder
            v
    IncidentAnalysisAgent          <- this module
            v
    IncidentAnalysisResult         <- implemented later, elsewhere

``IncidentAnalysisAgent`` builds the prompt, sends it to the model, and
returns an ``LLMResponse`` wrapping the model's raw text completely
unmodified, alongside metadata about the call itself. It does not
classify the incident, does not reason about forensic evidence, does not
parse or validate the model's answer, and does not generate a report --
those are the responsibilities of later stages (``IncidentAnalysisResult``
and the report generator), not of this module.

This module is independent from ``QwenValidator``
(``modules.llm.qwen_validator``): it does not import from, subclass, or
modify that module. It only reuses the same architectural seam --
today, a single ``_call_model`` placeholder method that isolates all
model-backend concerns -- so that a future real Qwen/Ollama integration
can be wired into both agents the same way, in one place each, without
either module depending on the other.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from modules.llm.incident_analysis_prompt_builder import IncidentAnalysisPromptBuilder


@dataclass(slots=True, frozen=True)
class LLMResponse:
    """
    The complete result of one call to the local model.

    ``text`` is exactly what analyze() is required to return: the
    model's raw response, completely unmodified -- no parsing, no JSON
    extraction, no regex, no cleanup. Every other field is metadata
    *about* that call, not about its content: nothing here is derived
    by reasoning about what the model said, so none of it crosses the
    "Python performs no forensic reasoning" line.

    This metadata exists because later stages (IncidentAnalysisResult,
    logging, auditing, cost/latency tracking) need more than the bare
    string -- and recovering `prompt`, `model_name`, or `duration`
    after the fact, once only `text` was kept, is not possible.

    `token_count` is the one exception: it is left `None` until a real
    backend can report it, rather than filled with any kind of
    approximation. See its field comment below for why.
    """

    text: str
    prompt: str
    model_name: str
    temperature: float
    duration_seconds: float
    # Left as None until a real backend is wired into `_call_model` and
    # can report actual token usage. Deliberately NOT a word-count or
    # any other approximation: an estimate that looks like a
    # measurement is worse than an honest "unknown" in a forensic
    # tool -- it invites a report to print a wrong number with no
    # indication that it's wrong.
    token_count: int | None = None


class IncidentAnalysisError(Exception):
    """
    Base class for every error raised by IncidentAnalysisAgent.

    Never raised directly -- callers should catch this to handle any
    failure of the analyze() pipeline without needing to know which
    stage (input validation, prompt construction, or model call)
    failed.
    """


class IncidentAnalysisInputError(IncidentAnalysisError):
    """
    Raised when the caller-supplied incident, timeline, or inventory
    context is not of the expected shape.

    This is not raised for legitimately empty evidence (an incident
    with an empty timeline or no inventory context is a normal,
    supported input -- IncidentAnalysisPromptBuilder already handles
    that gracefully). It is raised only when an argument is not the
    expected type at all, since letting that reach the prompt builder
    would fail with a confusing, unrelated error deeper in the call
    stack.
    """


class IncidentAnalysisPromptError(IncidentAnalysisError):
    """
    Raised when IncidentAnalysisPromptBuilder fails to build a prompt
    from otherwise well-typed inputs.
    """


class IncidentAnalysisModelError(IncidentAnalysisError):
    """
    Raised when the local model backend fails to produce a response
    (connection failure, timeout, backend/inference exception, or any
    other failure while communicating with the model).
    """


class IncidentAnalysisAgent:
    """
    Send a deterministic incident-analysis prompt to the local model
    and return its raw response, wrapped with call metadata.

    This class only orchestrates Evidence -> Prompt -> Model response.
    It does not decide what incident occurred, does not compute
    confidence, does not extract JSON or IOCs, and does not touch any
    incident, timeline, or inventory data beyond passing it to
    IncidentAnalysisPromptBuilder unchanged.
    """

    def __init__(
        self,
        prompt_builder: IncidentAnalysisPromptBuilder | None = None,
        model_name: str = "qwen-local",
        temperature: float = 0.0,
    ):
        """
        `prompt_builder` defaults to a new IncidentAnalysisPromptBuilder.
        Accepting one as a constructor argument keeps this class
        testable (a caller can inject a fake builder) without adding
        any behavior beyond what the default already provides.

        `model_name` and `temperature` are recorded on every
        LLMResponse this agent produces, and -- once a real backend
        replaces the placeholder in `_call_model` -- are the values
        that will actually be passed to that backend. They are plain
        configuration, never forensic logic.
        """

        self._prompt_builder = prompt_builder or IncidentAnalysisPromptBuilder()
        self._model_name = model_name
        self._temperature = temperature

    def analyze(
        self,
        serialized_incident: dict,
        timeline: list[dict],
        inventory_context: list[dict],
    ) -> LLMResponse:
        """
        Build the incident-analysis prompt and return the model's
        response.

        Parameters
        ----------
        serialized_incident:
            One incident payload as produced by
            ``IncidentSerializer.serialize()``.
        timeline:
            The forensic timeline as produced by
            ``TimelineBuilder.build()``. May be empty.
        inventory_context:
            Artifacts not parsed into normalized events (KAPE
            summary/console/copy/skip logs, unsupported or
            metadata-only artifacts, etc.). May be empty.

        Returns
        -------
        An LLMResponse whose `text` field is the model's response
        exactly as generated -- no parsing, no JSON extraction, no
        regex, no cleanup. Interpreting `text` is the responsibility
        of a later stage (IncidentAnalysisResult), not of this
        method. The remaining fields (`prompt`, `model_name`,
        `temperature`, `duration_seconds`, `token_count`) are metadata
        about the call, kept so later stages and logging don't have
        to reconstruct it after the fact.

        Raises
        ------
        IncidentAnalysisInputError:
            If an argument is not of the expected type.
        IncidentAnalysisPromptError:
            If prompt construction fails.
        IncidentAnalysisModelError:
            If the model backend fails to produce a response.
        """

        self._validate_inputs(serialized_incident, timeline, inventory_context)

        prompt = self._build_prompt(serialized_incident, timeline, inventory_context)

        return self._execute_model(prompt)

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_inputs(
        serialized_incident: dict,
        timeline: list[dict],
        inventory_context: list[dict],
    ) -> None:
        """
        Reject malformed inputs before they reach the prompt builder.

        An empty dict/list is valid (an incident may legitimately have
        no timeline events or no inventory artifacts yet); the wrong
        *type* is not, since IncidentAnalysisPromptBuilder's contract
        is plain dicts and lists of plain dicts.
        """

        if not isinstance(serialized_incident, dict):
            raise IncidentAnalysisInputError(
                "serialized_incident must be a dict, got "
                f"{type(serialized_incident).__name__}"
            )

        if not isinstance(timeline, list):
            raise IncidentAnalysisInputError(
                f"timeline must be a list, got {type(timeline).__name__}"
            )

        if not isinstance(inventory_context, list):
            raise IncidentAnalysisInputError(
                "inventory_context must be a list, got "
                f"{type(inventory_context).__name__}"
            )

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        serialized_incident: dict,
        timeline: list[dict],
        inventory_context: list[dict],
    ) -> str:
        """
        Delegate prompt construction to IncidentAnalysisPromptBuilder.

        Any failure here is wrapped in IncidentAnalysisPromptError so
        callers can distinguish "prompt construction failed" from
        "the model backend failed" without inspecting exception
        internals.
        """

        try:
            return self._prompt_builder.build(
                serialized_incident, timeline, inventory_context
            )
        except IncidentAnalysisError:
            raise
        except Exception as error:
            raise IncidentAnalysisPromptError(
                f"Failed to build incident analysis prompt: {error}"
            ) from error

    # ------------------------------------------------------------------
    # Model invocation
    # ------------------------------------------------------------------

    def _execute_model(self, prompt: str) -> LLMResponse:
        """
        Run the model backend via `_call_model` and wrap its raw
        response in an LLMResponse, timing the call and recording
        this agent's configured `model_name`/`temperature` alongside
        it.

        This method never inspects, interprets, or reasons about
        `text` -- it only measures how long producing it took and
        records what was asked for. All actual model communication
        stays inside `_call_model`; `token_count` is left `None`
        here rather than approximated, since only the real backend
        (once wired in) can report an actual token count.
        """

        start = time.perf_counter()
        text = self._call_model(prompt)
        duration_seconds = time.perf_counter() - start

        return LLMResponse(
            text=text,
            prompt=prompt,
            model_name=self._model_name,
            temperature=self._temperature,
            duration_seconds=duration_seconds,
            token_count=None,
        )

    @staticmethod
    def _call_model(prompt: str) -> str:
        """
        Send `prompt` to the local model backend and return its raw
        text response, unmodified.

        PLACEHOLDER: real model communication (Ollama, llama.cpp, or
        otherwise) is intentionally NOT implemented in this PR, for
        the same reason QwenValidator._call_model is a placeholder
        today -- no local Qwen client currently exists in this
        codebase to reuse. This method is the single, isolated seam
        where that integration will be added later, so swapping
        backends only ever means changing the body of this one
        method -- nothing else in IncidentAnalysisAgent depends on how
        the model is actually reached.

        Any failure while communicating with the model (connection
        failure, timeout, backend or inference exception) must raise
        IncidentAnalysisModelError rather than being swallowed, so
        callers always know analysis did not complete.
        """

        try:
            # Temporary mock implementation.
            # This method will later call the local Qwen backend
            # through Ollama, mirroring QwenValidator._call_model.
            return (
                "Placeholder response: no model backend is connected yet. "
                "This mock exists only to exercise the "
                "IncidentAnalysisAgent.analyze() orchestration path end "
                "to end. The real Qwen/Ollama call will replace this "
                "method body without changing analyze()'s signature or "
                "behavior."
            )
        except Exception as error:
            raise IncidentAnalysisModelError(
                f"Local model backend failed to produce a response: {error}"
            ) from error
