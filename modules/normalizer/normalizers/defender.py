from modules.normalizer.base_normalizer import BaseNormalizer
from modules.normalizer.event import create_event
from modules.models.event_type import EventType
from modules.models.event_category import EventCategory


class DefenderNormalizer(BaseNormalizer):

    def normalize(self, record :dict) -> list[dict]:

            if record.get("artifact_type") != "defender":
                return []

            message = record.get("message", "")
            message_lower = message.lower()

            
            

            component = (record.get("component") or "").lower()

            if "service started" in message_lower:
                event_type = EventType.DEFENDER_SERVICE_STARTED

            elif "service stopped" in message_lower:
                event_type = EventType.DEFENDER_SERVICE_STOPPED

            elif (
                "platform version" in message_lower
                or "engine version" in message_lower
                or "security intelligence version" in message_lower
                or "antivirus version" in message_lower
            ):
                event_type = EventType.DEFENDER_PLATFORM_UPDATE

            elif any(keyword in message_lower for keyword in (
                "threat",
                "malware",
                "detected",
                "quarantine",
                "remediation",
                "removed",
                "blocked",
                "infected",
            )):
                event_type = EventType.MALWARE_DETECTION

            elif "engine loaded" in message_lower:
                event_type = EventType.DEFENDER_ENGINE_LOADED

            elif "process scan" in message_lower and "started" in message_lower:
                event_type = EventType.DEFENDER_SCAN_STARTED

            elif "process scan" in message_lower and (
                    "completed" in message_lower
                    or "finished" in message_lower
            ):
                event_type = EventType.DEFENDER_SCAN_COMPLETED

            elif (
                component == "cloud"
                or "submitreport" in message_lower
                or "rpcspynet" in message_lower
            ):
                event_type = EventType.DEFENDER_CLOUD_REQUEST

            elif (
                "config change" in message_lower
                or "configuration" in message_lower
                or "refreshpluginconfiguration" in message_lower
            ):
                event_type = EventType.DEFENDER_CONFIGURATION_CHANGED

    
            else:
                event_type = EventType.DEFENDER_INFORMATION

            event = create_event(
                event_type=event_type,
                category=EventCategory.SECURITY,
                timestamp=record.get("timestamp"),
                artifact_type="defender",
                object_name=record.get("component"),
                object_path=None,
                description=message or f"Windows Defender event ({event_type.value})",
                evidence={
                    "record_type": record.get("record_type"),
                    "component": record.get("component"),
                    "action": record.get("action"),
                },
                source_file=record.get("source_path"),
                raw_data=record,
            )


            return [event]