from __future__ import annotations

import hashlib
from datetime import timedelta

from modules.correlation.context import RuleContext
from modules.correlation.models import Correlation
from modules.correlation.rules.base import Rule,correlation_id
from modules.correlation.sequence import combine_confidence, find_after
from modules.models.event_type import EventType
from modules.models.severity import Severity
from modules.normalizer.event import ensure_event_id


class BrowserDownloadExecutionRule(Rule):
    """
    Was a browser-downloaded file later executed (per Prefetch)?

    Matching is best-effort until Browser/Prefetch normalizers expose real
    identity_keys (SHA1, file_reference): entity_id is used when the
    resolver already fused the two events, otherwise a bare filename match
    is used as a weak fallback -- see sequence.find_after/best_effort_identity.
    This rule needs zero changes once those normalizers are enriched; it
    will simply start matching more often, and more reliably.

    Future MITRE mapping for this shape: T1105 (Ingress Tool Transfer) /
    T1204.002 (User Execution: Malicious File) -- not populated here,
    that's the MITRE Mapper's job downstream.
    """

    NAME = "browser_download_execution"

    _TITLE = "Downloaded file was executed"
    _DESCRIPTION = (
        "A file downloaded through the browser was later executed, "
        "per Prefetch."
    )

    # Generous on purpose: installers sitting in Downloads/ often get run
    # days after downloading, not within minutes. Narrow this if it proves
    # too noisy in practice -- an explicit, adjustable choice, not a fact.
    _WINDOW = timedelta(days=7)

    def run(self, context: RuleContext) -> list[Correlation]:
        downloads = []
        executions = []
        execution_entity_ids: dict[str, str] = {}

        for event_context in context.timeline:
            event = event_context.event

            if (
                event.get("artifact_type") == "browser"
                and event.get("event_type") == EventType.FILE_DOWNLOAD
            ):
                downloads.append(event_context)

            elif (
                event.get("artifact_type") == "prefetch"
                and event.get("event_type") == EventType.PROCESS_EXECUTION
            )or (
                event.get("artifact_type") == "evtx"
                and event.get("event_type") == EventType.POWERSHELL_PIPELINE_EXECUTION
            ):
                executions.append(event)
                if event_context.entity_id:
                    execution_entity_ids[event["event_id"]] = event_context.entity_id

        findings: list[Correlation] = []

        for download_context in downloads:
            download = download_context.event

            execution = find_after(
                download,
                executions,
                within=self._WINDOW,
                same_entity_id=download_context.entity_id,
                candidate_entity_ids=execution_entity_ids,
            )
            if execution is None:
                continue

            findings.append(
                self._to_correlation(download, execution, download_context.entity_id)
            )

        return findings

    def _to_correlation(
        self, download: dict, execution: dict, entity_id: str | None
    ) -> Correlation:
        download_id = ensure_event_id(download)
        execution_id = ensure_event_id(execution)

        evidence = {
            "download": dict(download.get("evidence") or {}),
            "execution": dict(execution.get("evidence") or {}),
            "download_path": download.get("object_path"),
            "executed_name": execution.get("object_name"),
        }

        return Correlation(
            correlation_id=correlation_id(
                self.NAME,
                download_id,
                execution_id,
            ),
            rule_name=self.NAME,
            title=self._TITLE,
            # MEDIUM, not LOW: download-then-execution close in time is a
            # genuinely more specific signal than either event alone --
            # still not definitive (installers do this legitimately too),
            # which is exactly what Behavior Detection resolves next.
            severity=Severity.MEDIUM,
            confidence=combine_confidence(
                download.get("confidence", 1.0), execution.get("confidence", 1.0)
            ),
            start_time=download["timestamp"],
            end_time=execution["timestamp"],
            event_ids=[download_id, execution_id],
            entity_ids=[entity_id] if entity_id else [],
            description=self._DESCRIPTION,
            evidence=evidence,
        )

    def _correlation_id(self, download_id: str, execution_id: str) -> str:
        digest = hashlib.sha256(
            f"{self.NAME}|{download_id}|{execution_id}".encode("utf-8")
        )
        return digest.hexdigest()