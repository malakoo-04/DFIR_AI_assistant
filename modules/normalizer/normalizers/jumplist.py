from modules.normalizer.base_normalizer import BaseNormalizer
from modules.normalizer.event import create_event

from modules.models.event_type import EventType
from modules.models.event_category import EventCategory


class JumpListNormalizer(BaseNormalizer):

    def normalize(self, record: dict) -> list[dict]:

        target = record.get("target_path")

        if target:
            object_name = target.split("\\")[-1]
        else:
            object_name = record.get("entry_name")

        description = "Jump List entry"

        if target:
            description = f"Recent access to {object_name}"

        event = create_event(

            artifact_type="jumplist",

            event_type=EventType.JUMPLIST_REFERENCE,

            category=EventCategory.USER_ACTIVITY,

            timestamp=record.get("access_time"),

            object_name=object_name,

            object_path=target,

            related_objects=[],

            user=None,

            computer=None,

            description=description,

            confidence=0.90,

            evidence={
                "entry_name": record.get("entry_name"),
                "jump_list_file": record.get("jump_list_file"),
                "stream_id": record.get("stream_id"),
                "entry_number": record.get("entry_number"),
                "relative_path": record.get("relative_path"),
                "working_directory": record.get("working_directory"),
                # Same distinction as in LNKNormalizer: this is the shortcut's
                # own embedded description, not the event's description above.
                "description": record.get("description"),
                "command_line_arguments": record.get("command_line_arguments"),
                "icon_location": record.get("icon_location"),
                "creation_time": record.get("creation_time"),
                "modified_time": record.get("modified_time"),
                "file_size": record.get("file_size"),
                "drive_serial": record.get("drive_serial"),
                "drive_type": record.get("drive_type"),
                "volume_label": record.get("volume_label"),
            },

            source_file=record.get("lnk_path"),

            raw_data=record,

        )

        return [event]