import xml.etree.ElementTree as ET

from modules.normalizer.base_normalizer import BaseNormalizer
from modules.normalizer.event import create_event

from modules.models.event_type import EventType
from modules.models.event_category import EventCategory


class EVTXNormalizer(BaseNormalizer):

    def normalize(self, record: dict) -> list[dict]:

        event_id = record.get("event_id")

        event_type = EventType.UNKNOWN_EVENT
        category = EventCategory.SYSTEM
        description = f"Windows Event {event_id}"

        if event_id == 4624:

            event_type = EventType.SUCCESSFUL_LOGON
            category = EventCategory.AUTHENTICATION
            description = "Successful logon"

        elif event_id == 4625:

            event_type = EventType.FAILED_LOGON
            category = EventCategory.AUTHENTICATION
            description = "Failed logon"

        elif event_id == 4688:

            event_type = EventType.PROCESS_EXECUTION
            category = EventCategory.EXECUTION
            description = "Process execution"

        elif event_id == 4689:

            event_type = EventType.PROCESS_TERMINATION
            category = EventCategory.EXECUTION
            description = "Process terminated"

        elif event_id == 7045:

            event_type = EventType.SERVICE_INSTALL
            category = EventCategory.PERSISTENCE
            description = "Service installed"

        elif event_id == 1102:

            event_type = EventType.LOG_CLEARED
            category = EventCategory.SYSTEM
            description = "Windows event log cleared"

        object_name = None
        object_path = None

        xml = record.get("xml")

        if xml:

            try:

                root = ET.fromstring(xml)

                ns = {
                    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
                }

                event_data = root.find("e:EventData", ns)

                if event_data is not None:

                    for data in event_data.findall("e:Data", ns):

                        name = data.attrib.get("Name")

                        value = data.text

                        if name in (
                            "NewProcessName",
                            "ProcessName",
                        ):

                            object_path = value

                            if value:

                                object_name = value.split("\\")[-1]

            except Exception:

                pass

        event = create_event(

            artifact_type="evtx",

            event_type=event_type,

            category=category,

            timestamp=record.get("timestamp"),

            object_name=object_name,

            object_path=object_path,

            related_objects=[],

            user=None,

            computer=record.get("computer"),

            description=description,

            confidence=1.0,

            evidence={
                "event_id": event_id,
                "provider": record.get("provider"),
                "channel": record.get("channel"),
                "record_id": record.get("record_id"),
            },

            source_file=record.get("source_path"),

            raw_data=record,

        )

        return [event]