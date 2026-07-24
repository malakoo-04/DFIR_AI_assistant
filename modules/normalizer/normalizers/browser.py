import os

from modules.normalizer.base_normalizer import BaseNormalizer
from modules.normalizer.event import create_event
from modules.models.event_type import EventType
from modules.models.event_category import EventCategory


class BrowserNormalizer(BaseNormalizer):

    def normalize(self, record: dict) -> list[dict]:

        events = []

        record_type = record.get("record_type")

        # ==========================
        # Browser History
        # ==========================

        if record_type == "history":

            event = create_event(

                artifact_type="browser",

                event_type=EventType.URL_VISIT,

                category=EventCategory.BROWSER,

                timestamp=record.get("visit_time"),

                object_name=record.get("title"),

                object_path=record.get("url"),

                related_objects=[],

                description=f"Visited {record.get('url')}",

                confidence=1.0,

                evidence={
                    "browser": record.get("browser"),
                    "visit_count": record.get("visit_count"),
                    "typed_count": record.get("typed_count"),
                    "last_visit_time": record.get("last_visit_time"),
                    "transition": record.get("transition"),
                    "visit_duration": record.get("visit_duration"),
                },

                source_file=record.get("source_path"),

                raw_data=record,

            )

            events.append(event)

        # ==========================
        # Downloads
        # ==========================

        elif record_type == "download":

            target_path = record.get("target_path")

            event = create_event(

                artifact_type="browser",

                event_type=EventType.FILE_DOWNLOAD,

                category=EventCategory.BROWSER,

                timestamp=record.get("start_time"),

                object_name=os.path.basename(target_path) if target_path else None,

                object_path=target_path,

                related_objects=[
                    record.get("site_url"),
                    record.get("tab_url"),
                ],

                description=f"Downloaded {target_path}",

                confidence=1.0,

                evidence={
                    "browser": record.get("browser"),
                    "current_path": record.get("current_path"),
                    "end_time": record.get("end_time"),
                    "received_bytes": record.get("received_bytes"),
                    "total_bytes": record.get("total_bytes"),
                    "state": record.get("state"),
                    "danger_type": record.get("danger_type"),
                    "referrer": record.get("referrer"),
                    "mime_type": record.get("mime_type"),
                },

                source_file=record.get("source_path"),

                raw_data=record,

            )

            events.append(event)

        return events