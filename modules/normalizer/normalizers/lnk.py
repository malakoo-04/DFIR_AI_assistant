from modules.normalizer.base_normalizer import BaseNormalizer
from modules.normalizer.event import create_event

from modules.models.event_type import EventType
from modules.models.event_category import EventCategory


class LNKNormalizer(BaseNormalizer):

    def normalize(self, record: dict) -> list[dict]:

        target = record.get("target_path")

        if target:
            object_name = target.split("\\")[-1]
        else:
            object_name = record.get("lnk_name")

        description = "Shortcut reference"

        if target:
            description = f"Shortcut referencing {object_name}"

        event = create_event(

            artifact_type="lnk",

            event_type=EventType.SHORTCUT_REFERENCE,

            category=EventCategory.USER_ACTIVITY,

            timestamp=record.get("modified_time"),

            object_name=object_name,

            object_path=target,

            related_objects=[],

            user=None,

            computer=None,

            description=description,

            confidence=0.80,

            evidence={
                "lnk_name": record.get("lnk_name"),
                "relative_path": record.get("relative_path"),
                "working_directory": record.get("working_directory"),
                # The .lnk file's own embedded description string — distinct
                # from create_event's "description" above, which describes
                # this normalized event, not the shortcut itself.
                "description": record.get("description"),
                "command_line_arguments": record.get("command_line_arguments"),
                "icon_location": record.get("icon_location"),
                "creation_time": record.get("creation_time"),
                "access_time": record.get("access_time"),
                "file_size": record.get("file_size"),
                "drive_serial": record.get("drive_serial"),
                "drive_type": record.get("drive_type"),
                "volume_label": record.get("volume_label"),
            },

            source_file=record.get("lnk_path"),

            raw_data=record,

        )

        return [event]