from modules.normalizer.base_normalizer import BaseNormalizer
from modules.normalizer.event import create_event
from modules.models.event_type import EventType
from modules.models.event_category import EventCategory


class ScheduledTaskNormalizer(BaseNormalizer):

    def normalize(self, record):

        if record.get("artifact_type") != "scheduled_task":
            return []

        command = record.get("command") or ""
        task_name = record.get("task_name") or ""

        event = create_event(
            event_type=EventType.PERSISTENCE,
            category=EventCategory.PERSISTENCE,
            timestamp=record.get("registration_date"),
            artifact_type="scheduled_task",
            object_name=task_name,
            object_path=command,
            user=record.get("user"),
            description=(
                f"Scheduled task '{task_name}' configured to run: {command}"
            ),
            evidence={
                "author": record.get("author"),
                "task_description": record.get("description"),
                "arguments": record.get("arguments"),
                "working_directory": record.get("working_directory"),
                "run_level": record.get("run_level"),
                "enabled": record.get("enabled"),
                "hidden": record.get("hidden"),
                "triggers": record.get("triggers"),
            },
            source_file=record.get("source_path"),
            raw_data=record,
        )

        return [event]