from modules.normalizer.base_normalizer import BaseNormalizer
from modules.normalizer.event import create_event
from modules.models.event_type import EventType
from modules.models.event_category import EventCategory


class PrefetchNormalizer(BaseNormalizer):

    def normalize(self, record: dict) -> list[dict]:

        events = []

        executable = record.get("filename")
        execution_times = record.get("last_run_times", [])
        referenced_files = record.get("loaded_files", [])
        source_path = record.get("source_path")

        for timestamp in execution_times:

            if timestamp is None:
                continue

            event = create_event(

                artifact_type="prefetch",

                event_type=EventType.PROCESS_EXECUTION,
                category=EventCategory.EXECUTION,

                timestamp=timestamp,

                object_name=executable,

                object_path=None,

                related_objects=referenced_files,

                description=f"{executable} was executed",

                confidence=0.95,

                evidence={
                    "prefetch_version": record.get("prefetch_version"),
                    "prefetch_hash": record.get("prefetch_hash"),
                    "run_count": record.get("run_count"),
                    "execution_slots": record.get("execution_slots"),
                    # All recorded run times for this executable, not just the
                    # single instant this event represents — useful context
                    # for how frequently/recently it ran overall.
                    "all_last_run_times": execution_times,
                    "loaded_files_count": record.get("loaded_files_count"),
                    "volumes": record.get("volumes"),
                    "volumes_count": record.get("volumes_count"),
                },

                source_file=source_path,

                raw_data=record,

            )

            events.append(event)

        return events