from __future__ import annotations

import re

from modules.correlation.context import RuleContext
from modules.correlation.models import Correlation
from modules.correlation.rules.base import Rule, correlation_id
from modules.models.event_type import EventType
from modules.models.severity import Severity
from modules.normalizer.event import ensure_event_id


class PowerShellExecutionRule(Rule):
    """
    Did PowerShell execute with indicators commonly associated with
    malicious use (execution policy bypass, encoded/obfuscated commands,
    reflective in-memory assembly loading, download cradles)?

    Reads from two artifact sources, deliberately: EVTX 4688 (a
    powershell.exe/pwsh.exe process was launched -- host-level view) and
    EVTX 800 (a specific pipeline ran inside an existing PowerShell host
    -- session-level view, richer via script_name/host_application). Both
    expose command-line text; this rule doesn't care which one produced
    the event, only whether the text matches known-suspicious patterns.
    """

    NAME = "powershell_execution"

    _POWERSHELL_EXECUTABLES = {"powershell.exe", "powershell_ise.exe", "pwsh.exe"}

    _INDICATORS = {
        "execution_policy_bypass": re.compile(r"-ep\s+bypass|-executionpolicy\s+bypass", re.IGNORECASE),
        "encoded_command": re.compile(r"-enc(?:odedcommand)?\b", re.IGNORECASE),
        "hidden_window": re.compile(r"-window(?:style)?\s+hidden", re.IGNORECASE),
        "reflective_load": re.compile(r"\[reflection\.assembly\]::load", re.IGNORECASE),
        "base64_payload": re.compile(r"frombase64string", re.IGNORECASE),
        "download_cradle": re.compile(
            r"net\.webclient|downloadstring|downloaddata|invoke-webrequest|\biwr\b", re.IGNORECASE
        ),
        "invoke_expression": re.compile(r"\biex\b|invoke-expression", re.IGNORECASE),
    }

    _INDICATOR_LABELS = {
        "execution_policy_bypass": "execution policy bypass",
        "encoded_command": "encoded command",
        "hidden_window": "hidden window",
        "reflective_load": "reflective in-memory assembly load",
        "base64_payload": "Base64-encoded payload",
        "download_cradle": "remote download cradle",
        "invoke_expression": "Invoke-Expression / IEX",
    }

    # Reflects actual capability, not just flag presence: reflective
    # in-memory loading and decoded Base64 payloads are what let code run
    # without ever touching disk -- the strongest signal here, and what
    # this exact dataset's real attack chain used. Bypass/encoded
    # commands/download cradles/IEX are common in legitimate admin
    # tooling too, so alone they only warrant MEDIUM. A hidden window by
    # itself is the weakest signal (routine scheduled automation hides
    # its window too) and never triggers a finding on its own.
    _HIGH_INDICATORS = {"reflective_load", "base64_payload"}
    _MEDIUM_INDICATORS = {"execution_policy_bypass", "encoded_command", "download_cradle", "invoke_expression"}

    # Keyword-based detection on command-line text is inherently
    # heuristic -- legitimate scripts use -ep bypass or IEX too. 0.75
    # reflects "worth an analyst's attention", not "confirmed malicious".
    _CONFIDENCE = 0.75

    def run(self, context: RuleContext) -> list[Correlation]:
        findings: list[Correlation] = []

        for event_context in context.timeline:
            event = event_context.event

            if event.get("artifact_type") != "evtx":
                continue

            event_type = event.get("event_type")

            if event_type == EventType.PROCESS_EXECUTION:
                if (event.get("object_name") or "").lower() not in self._POWERSHELL_EXECUTABLES:
                    continue
                # A real new process: both fields describe this one launch.
                text = " ".join(
                    str(value)
                    for value in (event.get("command_line"), event.get("host_application"))
                    if value
                )
            elif event_type == EventType.POWERSHELL_PIPELINE_EXECUTION:
                # host_application is the *session's* launch line, shared
                # by every pipeline step inside that session -- including
                # this event. Matching on it here would flag every
                # trivial step of a session merely because the session
                # itself was launched with e.g. -ep bypass. Only this
                # event's own command_line reflects what actually ran.
                text = str(event.get("command_line") or "")
            else:
                continue
            if not text:
                continue

            matched = {name for name, pattern in self._INDICATORS.items() if pattern.search(text)}
            if not matched:
                continue

            severity = self._severity_for(matched)
            if severity is None:
                continue

            findings.append(self._to_correlation(event, event_context.entity_id, matched, severity))

        return findings

    def _severity_for(self, matched: set[str]) -> Severity | None:
        if matched & self._HIGH_INDICATORS:
            return Severity.HIGH
        if matched & self._MEDIUM_INDICATORS:
            return Severity.MEDIUM
        return None  # hidden_window alone -- too weak by itself

    def _to_correlation(
        self, event: dict, entity_id: str | None, matched: set[str], severity: Severity
    ) -> Correlation:
        event_id = ensure_event_id(event)
        timestamp = event["timestamp"]

        evidence = {
            "matched_indicators": sorted(matched),
            "command_line": event.get("command_line"),
            "script_name": event.get("script_name"),
            "host_application": event.get("host_application"),
        }

        labels = sorted(self._INDICATOR_LABELS[name] for name in matched)

        return Correlation(
            correlation_id=correlation_id(self.NAME, event_id),
            rule_name=self.NAME,
            title="Suspicious PowerShell execution",
            severity=severity,
            confidence=self._CONFIDENCE,
            start_time=timestamp,
            end_time=timestamp,
            event_ids=[event_id],
            entity_ids=[entity_id] if entity_id else [],
            description="PowerShell execution matched: " + ", ".join(labels),
            evidence=evidence,
        )