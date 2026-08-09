from __future__ import annotations

from modules.llm.final_report.final_report_model import FinalReportModel
from modules.llm.final_report.final_report_prompt_builder import (
    FinalReportPromptBuilder,
)
from modules.llm.final_report.validator import FinalReportValidator


class FinalReportAgent:

    def __init__(self) -> None:

        self.model = FinalReportModel()
        self.prompt_builder = FinalReportPromptBuilder()
        self.validator = FinalReportValidator()

    def analyze(
        self,
        prioritized_incidents: list[dict],
        investigation_report: str,
        ioc_report: str,
    ) -> dict:

        prompt = self.prompt_builder.build(
            prioritized_incidents=prioritized_incidents,
            investigation_report=investigation_report,
            ioc_report=ioc_report,
        )

        response = self.model.generate(prompt)

        return self.validator.validate(response)