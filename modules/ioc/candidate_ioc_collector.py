from __future__ import annotations

from collections import OrderedDict


class CandidateIOCCollector:
    """
    Deterministically extract IOC candidates from serialized incidents.

    This class performs NO reasoning.

    It simply walks through the evidence already produced by the
    correlation engine and extracts values that could represent
    Indicators of Compromise.

    The LLM will later:
        - classify
        - deduplicate
        - score confidence
        - reject false positives

    This class only gathers candidate values.
    """

    IOC_FIELDS = {
        # Commands
        "command_line": "command_line",
        "powershell_command": "command_line",
        "cmd_command": "command_line",

        # Processes / executables
        "process_name": "process_name",
        "image": "process_name",
        "executed_name": "process_name",
        "object_name": "process_name",
        "exe": "process_name",

        # Files
        "filename": "filename",
        "download_name": "filename",
        "downloaded_file": "filename",
        "downloaded_filename": "filename",
        "object_path": "file_path",
        "image_path": "file_path",
        "target_path": "file_path",
        "file_path": "file_path",

        # Registry
        "registry_key": "registry_key",
        "registry_value": "registry_value",
        "key_path": "registry_key",

        # Persistence
        "service_name": "service_name",
        "task_name": "scheduled_task",
        "task_path": "scheduled_task",

        # Network
        "url": "url",
        "download_url": "url",
        "referrer": "url",
        "domain": "domain",
        "hostname": "hostname",
        "host": "hostname",
        "ip": "ip_address",
        "ipv4": "ip_address",
        "ipv6": "ip_address",

        # Hashes
        "sha256": "sha256",
        "sha1": "sha1",
        "md5": "md5",
        "hash": "hash",

        # Users
        "user": "username",
        "username": "username",
        "account": "username",

        # Ransomware
        "ransom_note": "filename",
        "readme": "filename",
}

    def collect(
        self,
        prioritized_incidents: list[dict],
    ) -> list[dict]:

        candidates = OrderedDict()

        for incident in prioritized_incidents:

            incident_id = incident.get("incident_id", "")

            correlations = (
                incident.get("primary_correlations", [])
                + incident.get("supporting_correlations", [])
            )

            for correlation in correlations:

                correlation_id = correlation.get("correlation_id", "")

                evidence = correlation.get("evidence") or {}

                for key, value in evidence.items():

                    if key not in self.IOC_FIELDS:
                        continue

                    self._add_candidate(
                        candidates,
                        self.IOC_FIELDS[key],
                        value,
                        incident_id,
                        correlation_id,
                    )
        print(f"Candidate IOCs: {len(candidates)}")
        return list(candidates.values())

    def _add_candidate(
        self,
        candidates: OrderedDict,
        candidate_type: str,
        value,
        incident_id: str,
        correlation_id: str,
    ):

        if value is None:
            return

        if isinstance(value, list):
            for item in value:
                self._add_candidate(
                    candidates,
                    candidate_type,
                    item,
                    incident_id,
                    correlation_id,
                )
            return

        if isinstance(value, dict):
            return

        value = str(value).strip()
        value = value.replace("\x00", "")
        if len(value) > 1000:
           value = value[:1000] + " ...<TRUNCATED>"

        # -------------------------------------------------------
        # Compress huge PowerShell commands
        # -------------------------------------------------------

        lower = value.lower()

        if candidate_type == "command_line":

            # Remove gigantic Base64 payloads
            import re

            # Replace long Base64 blobs anywhere in the command
            value = re.sub(
                r"[A-Za-z0-9+/=]{200,}",
                "<BASE64_PAYLOAD>",
                value,
            )

            # Truncate absurdly long commands
            if len(value) > 800:
                value = value[:800] + " ...<TRUNCATED>"

        LOW_VALUE = {
            "",
            "-",
            ".",
            "none",
            "null",
            "unknown",
            "true",
            "false",
            "0",
            "1",
        }

        if value.lower() in LOW_VALUE:
            return
        if len(value) < 3:
            return

        if not value:
            return

        key = (candidate_type, value.lower())

        if key in candidates:
            candidates[key]["occurrences"] += 1

            sources = candidates[key].setdefault("sources", [])

            if len(sources) < 3:
                sources.append(
                    {
                        "incident_id": incident_id,
                        "correlation_id": correlation_id,
                    }
                )

            return

        WINDOWS_NOISE = (
            "c:\\windows\\system32",
            "c:\\windows\\winsxs",
            "c:\\program files\\windows defender",
            "c:\\programdata\\microsoft",
        )

        BENIGN_SERVICES = {
            "appreadiness",
            "ksecpkg",
            "edgeupdate",
            "edgeupdatem",
            "w32time",
            "eventlog",
            "rpcss",
            "lanmanserver",
            "lanmanworkstation",
        }

        lower = value.lower()

        if any(lower.startswith(path) for path in WINDOWS_NOISE):
            return
        if candidate_type == "service_name":
            if lower.replace("\x00", "").strip() in BENIGN_SERVICES:
                return

        if candidate_type == "registry_key":

            if "\\services\\appreadiness" in lower:
                return

            if "\\services\\ksecpkg" in lower:
                return

            if "\\services\\edgeupdate" in lower:
                return    

            
        candidates[key] = {
            "type": candidate_type,
            "value": value,
            "occurrences": 1,
            "source": {
                "incident_id": incident_id,
                "correlation_id": correlation_id,
            },
            "sources": [
                {
                    "incident_id": incident_id,
                    "correlation_id": correlation_id,
                }
            ],
                    }