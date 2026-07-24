from pathlib import Path
import re
from datetime import datetime

from modules.parsers.base_parser import BaseParser


class DefenderParser(BaseParser):
    """
    Generic Microsoft Defender log parser.
    Supports MPLog and MPDetection logs.
    """

    TIMESTAMP_RE = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T.*?Z)\s*(?P<message>.*)$"
    )

    COMPONENT_RE = re.compile(
        r"^\[(?P<component>[^\]]+)\]\s*(?P<message>.*)$"
    )

    ACTION_RE = re.compile(
        r"^(?P<action>[A-Za-z0-9 _\-/]+?)(?:\:|\(|\.|$)"
    )

    def parse(self, artifact_path: Path) -> list[dict]:

        filename = artifact_path.name.lower()

        if "mpdetection" in filename:
            return self._parse_detection(artifact_path)

        if "mplog" in filename:
            return self._parse_mplog(artifact_path)

        return []

    def _parse_mplog(self, artifact_path: Path) -> list[dict]:

        results = []

        with artifact_path.open(
            "r",
            encoding="utf-16-le",
            errors="ignore"
        ) as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                match = self.TIMESTAMP_RE.match(line)

                if not match:
                    continue

                timestamp = self._parse_timestamp(
                    match.group("timestamp")
                )

                message = match.group("message")

                component = None

                component_match = self.COMPONENT_RE.match(message)

                if component_match:

                    component = component_match.group("component")
                    message = component_match.group("message")

                action = self._extract_action(message)

                results.append({

                    "artifact_type": "defender",

                    "record_type": "service_log",

                    "timestamp": timestamp,

                    "component": component,

                    "action": action,

                    "message": message,

                    "source_path": str(artifact_path)

                })

        return results

    def _parse_detection(self, artifact_path: Path) -> list[dict]:

        results = []

        with artifact_path.open(
            "r",
            encoding="utf-16-le",
            errors="ignore"
        ) as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                match = self.TIMESTAMP_RE.match(line)

                if not match:
                    continue

                message = match.group("message")

                results.append({

                    "artifact_type": "defender",

                    "record_type": "detection_log",

                    "timestamp": self._parse_timestamp(
                        match.group("timestamp")
                    ),

                    "component": None,

                    "action": self._extract_action(message),

                    "message": message,

                    "source_path": str(artifact_path)

                })

        return results

    def _extract_action(self, message: str) -> str | None:

        match = self.ACTION_RE.match(message)

        if match:
            return match.group("action").strip()

        return None

    def _parse_timestamp(self, value: str):

        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except Exception:
            return None