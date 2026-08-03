"""Prompt -> local model boundary for the Incident Analysis Agent.

This module is the orchestration seam between the deterministic forensic
pipeline (``IncidentSerializer`` -> ``IncidentAnalysisPromptBuilder``) and
the local Qwen model. It performs no reasoning of its own:

    IncidentSerializer
            v
    IncidentAnalysisPromptBuilder
            v
    IncidentAnalysisAgent         <- this module
            v
    IncidentAnalysisResult        <- implemented later, elsewhere

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

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from modules.llm.incident_analysis_prompt_builder import IncidentAnalysisPromptBuilder


@dataclass(slots=True, frozen=True)
class LLMResponse:
    """The complete result of one call to the local model."""

    text: str
    prompt: str
    model_name: str
    temperature: float
    duration_seconds: float
    token_count: int | None = None


class IncidentAnalysisError(Exception):
    """Base class for every error raised by IncidentAnalysisAgent."""


class IncidentAnalysisInputError(IncidentAnalysisError):
    """Raised when the input context is not of the expected shape."""


class IncidentAnalysisPromptError(IncidentAnalysisError):
    """Raised when IncidentAnalysisPromptBuilder fails to build a prompt."""


class IncidentAnalysisModelError(IncidentAnalysisError):
    """Raised when the local model backend fails to produce a response."""


class IncidentAnalysisAgent:
    """Send a deterministic incident-analysis prompt to the local model

    and return its raw response, wrapped with call metadata.
    """

    def __init__(
        self,
        prompt_builder: IncidentAnalysisPromptBuilder | None = None,
        model_name: str = "qwen2.5:7b",
        temperature: float = 0.0,
        ollama_host: str = "http://localhost:11434",
        timeout_seconds: float = 180.0,
        keep_alive: str | int = "30m",
    ):
        """Parameters

        ----------
        timeout_seconds:
            Since the fix below, this is an **idle timeout**: the
            maximum gap allowed between two consecutive pieces of
            streamed output, not a ceiling on total call duration.
            Previously (``stream: false``, a single blocking read of
            the full response) this was a total-duration cap, and a
            slow-but-working CPU generation could exceed it even
            though nothing was actually stuck -- that's what was
            timing out despite `ollama run` succeeding on the exact
            same prompt. 180s of *silence* is a reasonable "something
            is actually wrong" signal; 180s of *total* generation time
            for a 14B CPU model on a real prompt is not. If you still
            see timeouts after this change, that's a real stall (or a
            genuinely dead Ollama), not slow-but-alive generation --
            worth raising, not just raising the number again.
        keep_alive:
            Forwarded to Ollama as-is (duration string like "30m", a
            number of seconds, or -1 to never unload). Ollama's own
            default is 5 minutes; if the deterministic Python stages
            between two incidents in a batch run ever take longer
            than that, the model gets unloaded and the next call pays
            a full reload (multi-minute, on a CPU-hosted 14B model)
            before it can even start generating. 30 minutes comfortably
            survives normal per-incident processing gaps without
            keeping the model loaded forever after the batch ends.
        """
        self._prompt_builder = prompt_builder or IncidentAnalysisPromptBuilder()
        self._model_name = model_name
        self._temperature = temperature
        self._ollama_host = ollama_host
        self._timeout_seconds = timeout_seconds
        self._keep_alive = keep_alive

    def analyze(
        self,
        serialized_incident: dict,
        timeline: list[dict],
        inventory_context: list[dict],
    ) -> LLMResponse:
        """Build the incident-analysis prompt and return the model's response."""
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
        """Dump `prompt` to `prompt.txt` before invoking the model backend."""
        with open("prompt.txt", "w", encoding="utf-8") as file:
            file.write(prompt)

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

    def _call_model(self, prompt: str) -> str:
        payload = json.dumps(
            {
                "model": self._model_name,
                "prompt": prompt,
                "stream": True,
                "keep_alive": self._keep_alive,
                "options": {
                    "temperature": self._temperature,
                },
            }
        ).encode("utf-8")

        request = urllib.request.Request(
            f"{self._ollama_host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request, timeout=self._timeout_seconds
            ) as response:
                return self._consume_stream(response)
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            raise IncidentAnalysisModelError(
                f"HTTP {error.code}\n\n{body}"
            ) from error
        except urllib.error.URLError as error:
            raise IncidentAnalysisModelError(
                f"Could not reach Ollama at {self._ollama_host}: {error}"
            ) from error
        except TimeoutError as error:
            raise IncidentAnalysisModelError(
                f"Ollama produced no new output for over "
                f"{self._timeout_seconds:.0f}s (idle timeout, not a total "
                f"call-duration timeout) -- the model may be stuck or the "
                f"Ollama process may have died mid-generation: {error}"
            ) from error
        except Exception as error:
            raise IncidentAnalysisModelError(
                f"Failed during request to Ollama: {error}"
            ) from error

    def _consume_stream(self, response) -> str:
        """Accumulate Ollama's newline-delimited JSON stream into the

        final response text.

        Each line is one JSON object, typically carrying a fragment of
        the response in ``"response"``; the final line carries
        ``"done": true``. Because this reads the socket line by line
        rather than waiting for one single complete response body, the
        ``timeout`` passed to ``urlopen`` above behaves as an idle
        timeout -- it only fires if no new line arrives within that
        window, regardless of how long the overall generation takes.
        """
        chunks: list[str] = []
        saw_done = False

        for raw_line in response:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as error:
                raise IncidentAnalysisModelError(
                    f"Ollama streamed a non-JSON line: {error}"
                ) from error

            if "error" in parsed:
                raise IncidentAnalysisModelError(
                    f"Ollama returned an error for model '{self._model_name}': "
                    f"{parsed['error']} (is it pulled? try `ollama pull {self._model_name}`)"
                )

            chunks.append(parsed.get("response", ""))

            if parsed.get("done"):
                saw_done = True
                break

        if not saw_done:
            raise IncidentAnalysisModelError(
                "Ollama's stream ended without a final done=true message -- "
                "the connection was likely closed early."
            )

        return "".join(chunks)