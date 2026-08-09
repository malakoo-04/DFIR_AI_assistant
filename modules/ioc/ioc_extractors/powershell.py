from __future__ import annotations

from modules.ioc.ioc_context import IOCExtractionContext
from modules.ioc.ioc_extractors.base import BaseIOCExtractor
from modules.ioc.ioc_models import IOC, IOCType


class PowerShellIOCExtractor(BaseIOCExtractor):
    """
    Command lines and script names from PowerShell-related events and
    correlations (EVTX 4688/800 command_line/script_name fields, and
    powershell_execution's own matched-indicator evidence).
    """

    def extract(self, context: IOCExtractionContext) -> list[IOC]:
        iocs: list[IOC] = []

        for event in context.timeline:
            command_line = event.get("command_line") or (event.get("evidence") or {}).get("command_line")
            script_name = event.get("script_name") or (event.get("evidence") or {}).get("script_name")

            if command_line:
                iocs.append(self._command_line_ioc(command_line, event))
            if script_name:
                iocs.append(self._script_ioc(script_name, event))

        for correlation in context.correlations:
            if correlation.rule_name != "powershell_execution":
                continue

            evidence = correlation.evidence or {}
            command_line = evidence.get("command_line")
            script_name = evidence.get("script_name")
            matched = evidence.get("matched_indicators") or []

            if command_line:
                ioc = self._command_line_ioc(command_line, None)
                ioc.related_correlation_ids = {correlation.correlation_id}
                ioc.related_event_ids = set(correlation.event_ids)
                ioc.related_incident_ids = set(context.incidents_for(correlation.correlation_id))
                ioc.confidence = correlation.confidence
                ioc.severity = correlation.severity
                ioc.first_seen = ioc.last_seen = correlation.start_time
                ioc.supporting_evidence = [
                    f"matched indicators: {', '.join(matched)}"
                ] if matched else []
                iocs.append(ioc)

            if script_name:
                ioc = self._script_ioc(script_name, None)
                ioc.related_correlation_ids = {correlation.correlation_id}
                ioc.related_event_ids = set(correlation.event_ids)
                ioc.related_incident_ids = set(context.incidents_for(correlation.correlation_id))
                ioc.confidence = correlation.confidence
                ioc.severity = correlation.severity
                ioc.first_seen = ioc.last_seen = correlation.start_time
                iocs.append(ioc)

        return iocs

    @staticmethod
    def _command_line_ioc(command_line: str, event: dict | None) -> IOC:
        return IOC(
            ioc_type=IOCType.COMMAND_LINE,
            value=command_line,
            source_artifact=str((event or {}).get("artifact_type") or "evtx"),
            first_seen=(event or {}).get("timestamp"),
            last_seen=(event or {}).get("timestamp"),
            confidence=float((event or {}).get("confidence", 0.5) or 0.5),
            related_event_ids={event["event_id"]} if event and event.get("event_id") else set(),
        )

    @staticmethod
    def _script_ioc(script_name: str, event: dict | None) -> IOC:
        return IOC(
            ioc_type=IOCType.POWERSHELL_SCRIPT,
            value=script_name,
            source_artifact=str((event or {}).get("artifact_type") or "evtx"),
            first_seen=(event or {}).get("timestamp"),
            last_seen=(event or {}).get("timestamp"),
            confidence=float((event or {}).get("confidence", 0.5) or 0.5),
            related_event_ids={event["event_id"]} if event and event.get("event_id") else set(),
        )