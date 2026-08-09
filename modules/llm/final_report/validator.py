from __future__ import annotations


class FinalReportValidationError(Exception):
    pass


class FinalReportValidator:

    def validate(
        self,
        report: str,
    ) -> str:

        if not report:
            raise FinalReportValidationError(
                "Empty report."
            )

        report = report.strip()

        if len(report) < 100:
            raise FinalReportValidationError(
                "Generated report is too short."
            )

        return report