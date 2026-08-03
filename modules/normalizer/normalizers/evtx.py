from __future__ import annotations

import xml.etree.ElementTree as ET

from modules.models.event_category import EventCategory
from modules.models.event_type import EventType
from modules.normalizer.base_normalizer import BaseNormalizer
from modules.normalizer.event import create_event


class EVTXNormalizer(BaseNormalizer):

    # Standard Windows EVTX Provider Constants
    PROVIDER_SECURITY = "Microsoft-Windows-Security-Auditing"
    PROVIDER_SCM = "Service Control Manager"
    PROVIDER_EVENTLOG = "Microsoft-Windows-Eventlog"
    PROVIDER_POWERSHELL = "PowerShell"

    # Windows Event IDs are only unique within a Provider.
    # Mapping is indexed on tuple: (provider, event_id)
    _EVENT_MAP = {
        (PROVIDER_SECURITY, 4624): (
            EventType.SUCCESSFUL_LOGON,
            EventCategory.AUTHENTICATION,
            "Successful logon",
        ),
        (PROVIDER_SECURITY, 4625): (
            EventType.FAILED_LOGON,
            EventCategory.AUTHENTICATION,
            "Failed logon",
        ),
        (PROVIDER_SECURITY, 4688): (
            EventType.PROCESS_EXECUTION,
            EventCategory.EXECUTION,
            "Process execution",
        ),
        (PROVIDER_SECURITY, 4689): (
            EventType.PROCESS_TERMINATION,
            EventCategory.EXECUTION,
            "Process terminated",
        ),
        (PROVIDER_SCM, 7045): (
            EventType.SERVICE_INSTALL,
            EventCategory.PERSISTENCE,
            "Service installed",
        ),
        (PROVIDER_EVENTLOG, 1102): (
            EventType.LOG_CLEARED,
            EventCategory.SYSTEM,
            "Windows event log cleared",
        ),
        (PROVIDER_EVENTLOG, 104): (
            EventType.LOG_CLEARED,
            EventCategory.SYSTEM,
            "Windows event log cleared",
        ),
        (PROVIDER_POWERSHELL, 800): (
            EventType.POWERSHELL_PIPELINE_EXECUTION,
            EventCategory.EXECUTION,
            "PowerShell pipeline execution",
        ),
    }

    def normalize(self, record: dict) -> list[dict]:
        event_id = record.get("event_id")
        provider = (record.get("provider") or "").strip()

        mapped = self._EVENT_MAP.get((provider, event_id))

        if mapped is not None:
            event_type, category, description = mapped
        else:
            event_type = EventType.UNKNOWN_EVENT
            category = EventCategory.SYSTEM
            description = (
                f"Windows Event {event_id} ({provider})"
                if provider
                else f"Windows Event {event_id}"
            )

        object_name: str | None = None
        object_path: str | None = None
        extracted_user: str | None = None

        xml = record.get("xml")

        if xml:
            try:
                root = ET.fromstring(xml)
                ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                event_data = root.find("e:EventData", ns)

                if event_data is not None:
                    for data in event_data.findall("e:Data", ns):
                        name = data.attrib.get("Name")
                        value = data.text

                        if not value:
                            continue

                        # Extract Process executable paths
                        if name in ("NewProcessName", "ProcessName"):
                            object_path = value
                            object_name = value.split("\\")[-1]

                        # Extract User identities if present in event data
                        elif (
                            name in ("TargetUserName", "SubjectUserName")
                            and value != "-"
                        ):
                            extracted_user = value

            except Exception:
                # Silently ignore malformed XML chunks to prevent pipeline failure
                pass

        # Event 800 has no Name-attributed <Data> elements at all
        # (see evtx_parser's dedicated Event 800 sub-parser), so the
        # loop above never populates object_name/object_path for
        # it. script_name -- when present -- is the one clean,
        # exact-path signal this event type can offer.
        if event_id == 800 and record.get("script_name"):
            object_path = record.get("script_name")
            object_name = object_path.split("\\")[-1]

        # Set dynamic description if script name exists for PowerShell pipeline executions
        if (
            event_type == EventType.POWERSHELL_PIPELINE_EXECUTION
            and record.get("script_name")
        ):
            description = f"PowerShell script executed: {record.get('script_name')}"

        event = create_event(
            artifact_type="evtx",
            event_type=event_type,
            category=category,
            timestamp=record.get("timestamp"),
            object_name=object_name,
            object_path=object_path,
            related_objects=[],
            user=extracted_user or record.get("user"),
            computer=record.get("computer"),
            description=description,
            confidence=1.0,
            evidence={
                "event_id": event_id,
                "provider": provider,
                "channel": record.get("channel"),
                "record_id": record.get("record_id"),
                "command_line": record.get("command_line"),
                "script_name": record.get("script_name"),
                "host_application": record.get("host_application"),
                "command_summary": record.get("command_summary"),
            },
            source_file=record.get("source_path"),
            raw_data=record,
            record_id=record.get("record_id"),
        )
        event["command_line"] = record.get("command_line")
        event["script_name"] = record.get("script_name")
        event["host_application"] = record.get("host_application")

        return [event]