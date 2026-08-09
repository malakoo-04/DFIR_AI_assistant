from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from modules.ioc.candidate_ioc_collector import CandidateIOCCollector
from modules.llm.ioc_extraction_prompt_builder import IOCExtractionPromptBuilder
from modules.llm.ioc_models import IOCReport
from modules.llm.ioc_validator import IOCValidationError, QwenIOCValidator

import os
import time

from dotenv import load_dotenv
from google import genai
load_dotenv()
@dataclass(slots=True, frozen=True)
class IOCExtractionResult:
    """The complete result of one IOC extraction run."""

    report: IOCReport
    raw_response: str
    prompt: str
    model_name: str
    temperature: float
    duration_seconds: float
    attempts: int
    incident_count: int
    detailed_incident_count: int


class IOCExtractionError(Exception):
    """Base class for every error raised by IOCExtractionAgent."""


class IOCExtractionInputError(IOCExtractionError):
    """Raised when the input context is not of the expected shape."""


class IOCExtractionPromptError(IOCExtractionError):
    """Raised when IOCExtractionPromptBuilder fails to build a prompt."""


class IOCExtractionModelError(IOCExtractionError):
    """Raised when the local model backend fails to produce a response."""


class IOCExtractionValidationError(IOCExtractionError):
    """Raised when the model's response still fails validation after
    every retry has been exhausted."""


class IOCExtractionAgent:
    """Send the deterministic IOC-extraction prompt to the local model,
    validate its JSON response, and return a validated IOCReport.

    Independent of InvestigationAnalysisAgent: it does not import from
    it, does not reuse its prompt, and does not depend on Agent 1
    having run first -- it only needs candidate IOCs extracted from pipeline inputs.
    """

    def __init__(
        self,
        prompt_builder: IOCExtractionPromptBuilder | None = None,
        validator: QwenIOCValidator | None = None,
        model_name: str = "gemini-3.5-flash",
        temperature: float = 0.0,
        
      
        max_retries: int = 2,
    ):
        self._prompt_builder = (
            prompt_builder
            or IOCExtractionPromptBuilder(max_detailed_incidents=40)
        )
        self._model_name = model_name
        self._validator = validator or QwenIOCValidator()
        self._collector = CandidateIOCCollector()
       
        self._temperature = temperature
       
        
        self._max_retries = max_retries

    def extract(
            self,
            prioritized_incidents: list[dict],
            timeline: list[dict],
            inventory_context: list[dict],
            attack_chain: list[dict] | dict | None = None,
        ) -> IOCExtractionResult:

            self._validate_inputs(
                prioritized_incidents,
                timeline,
                inventory_context,
            )

            candidate_iocs = self._collector.collect(
                prioritized_incidents
            )

            start = time.perf_counter()

            all_iocs = []
            all_raw = []
            total_attempts = 0

            BATCH_SIZE = 250

            for i in range(0, len(candidate_iocs), BATCH_SIZE):

                batch = candidate_iocs[i:i + BATCH_SIZE]

                print(
                    f"IOC batch {i // BATCH_SIZE + 1} "
                    f"({len(batch)} candidates)"
                )

                prompt = self._build_prompt(batch)

                raw_response, attempts = self._call_with_retries(
                    prompt
                )

                total_attempts += attempts

                all_raw.append(raw_response)

                try:

                    report = self._validator.validate(
                        raw_response
                    )

                    all_iocs.extend(report.iocs)

                except IOCValidationError as error:

                    raise IOCExtractionValidationError(
                        f"Batch {i // BATCH_SIZE + 1} failed validation: {error}"
                    ) from error

            duration_seconds = (
                time.perf_counter() - start
            )
            largest = max(
                batch,
                key=lambda x: len(json.dumps(x))
            )

            print(
                "Largest IOC:",
                len(json.dumps(largest))
            )

            # ---------------------------------------------
            # Deduplicate final IOC list
            # ---------------------------------------------

            unique = {}

            for ioc in all_iocs:

                key = (
                    ioc.type.value,
                    ioc.value.lower(),
                )

                unique[key] = ioc

            final_report = IOCReport(
                iocs=list(unique.values())
            )

            return IOCExtractionResult(
                report=final_report,
                raw_response="\n\n".join(all_raw),
                prompt=f"{len(candidate_iocs)} IOC candidates",
                model_name=self._model_name,
                temperature=self._temperature,
                duration_seconds=duration_seconds,
                attempts=total_attempts,
                incident_count=len(prioritized_incidents),
                detailed_incident_count=len(candidate_iocs),
            )
    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_inputs(
        prioritized_incidents: list[dict],
        timeline: list[dict],
        inventory_context: list[dict],
    ) -> None:
        if not isinstance(prioritized_incidents, list):
            raise IOCExtractionInputError(
                "prioritized_incidents must be a list, got "
                f"{type(prioritized_incidents).__name__}"
            )
        if not isinstance(timeline, list):
            raise IOCExtractionInputError(
                f"timeline must be a list, got {type(timeline).__name__}"
            )
        if not isinstance(inventory_context, list):
            raise IOCExtractionInputError(
                "inventory_context must be a list, got "
                f"{type(inventory_context).__name__}"
            )

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        candidate_iocs: list[dict],
    ) -> str:
        try:
            return self._prompt_builder.build(candidate_iocs)
        except IOCExtractionError:
            raise
        except Exception as error:
            raise IOCExtractionPromptError(
                f"Failed to build IOC extraction prompt: {error}"
            ) from error

    # ------------------------------------------------------------------
    # Model invocation + retry-on-malformed-JSON
    # ------------------------------------------------------------------

    def _call_with_retries(self, prompt: str) -> tuple[str, int]:
        current_prompt = prompt
        last_raw_response = ""

        for attempt in range(1, self._max_retries + 2):
            raw_response = self._call_model(current_prompt)
            last_raw_response = raw_response

            try:
                self._validator.validate(raw_response)
                return raw_response, attempt
            except IOCValidationError as error:
                if attempt == self._max_retries + 1:
                    break
                current_prompt = self._build_retry_prompt(prompt, raw_response, error)

        return last_raw_response, self._max_retries + 1

    @staticmethod
    def _build_retry_prompt(
        original_prompt: str, previous_response: str, error: IOCValidationError
    ) -> str:
        return "\n\n".join(
            [
                original_prompt,
                "# CORRECTION REQUIRED",
                "",
                "Your previous response did not satisfy the OUTPUT CONTRACT:",
                f"  {error}",
                "",
                "Your previous response was:",
                previous_response,
                "",
                "Respond again. Output ONLY one valid JSON object matching",
                "the OUTPUT CONTRACT exactly -- no Markdown, no code fences,",
                "no explanation, no text before or after the JSON.",
            ]
        )

    def _call_model(self, prompt: str) -> str:

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise IOCExtractionModelError(
                "GEMINI_API_KEY not found in .env"
            )

        client = genai.Client(api_key=api_key)

        try:

            response = client.models.generate_content(
                model=self._model_name,
                contents=prompt,
            )

            if not response.text:
                raise IOCExtractionModelError(
                    "Gemini returned an empty response."
                )

            return response.text

        except Exception as error:
            raise IOCExtractionModelError(
                f"Gemini API error: {error}"
            ) from error    