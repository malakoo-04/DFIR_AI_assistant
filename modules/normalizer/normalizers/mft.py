from modules.normalizer.base_normalizer import BaseNormalizer
from modules.normalizer.event import create_event
from modules.models.event_type import EventType
from modules.models.event_category import EventCategory
from datetime import timedelta

def timestamps_differ(a, b):
        if a is None or b is None:
            return False

        return abs(a - b) > timedelta(seconds=2)

class MFTNormalizer(BaseNormalizer):
    """
    Normalizer du Master File Table ($MFT).
    Produit uniquement les événements forensiques pertinents.
    """

    def normalize(self, record: dict) -> list[dict]:

        events = []

        object_name = record.get("filename")
        object_path = record.get("primary_path")

        base_evidence = {
            "file_reference": record.get("file_reference"),
            "mft_reference": record.get("mft_reference"),
            "sequence_number": record.get("sequence_number"),
            "alternate_filenames": record.get("alternate_filenames", []),
            "alternate_paths": record.get("alternate_paths", []),
            "allocated_size": record.get("allocated_size"),
            "real_size": record.get("real_size"),
            "file_attributes": record.get("file_attributes"),
            "usn": record.get("usn"),
        }

        # --------------------------------------------------
        # File / Directory creation
        # --------------------------------------------------

        if record.get("si_created"):

            if record.get("is_directory"):

                events.append(
                    create_event(
                        timestamp=record["si_created"],
                        artifact_type="mft",
                        event_type=EventType.DIRECTORY_CREATED,
                        category=EventCategory.FILESYSTEM,
                        object_name=object_name,
                        object_path=object_path,
                        description=f"Directory created: {record.get('primary_path')}",
                        source_file=record.get("source_path"),
                        # Copied so this event's evidence can't be mutated
                        # through a shared reference with other events built
                        # from the same MFT record (e.g. creation + deletion).
                        evidence=dict(base_evidence),
                    )
                )

            else:

                events.append(
                    create_event(
                        timestamp=record["si_created"],
                        artifact_type="mft",
                        event_type=EventType.FILE_CREATION,
                        category=EventCategory.FILESYSTEM,
                        object_name=object_name,
                        object_path=object_path,
                        description=f"File created: {record.get('primary_path')}",
                        source_file=record.get("source_path"),
                        evidence=dict(base_evidence),
                    )
                )

        # --------------------------------------------------
        # Deleted entries
        # --------------------------------------------------

        if not record.get("in_use"):

            deletion_time = (
                record.get("si_entry_modified")
                or record.get("fn_entry_modified")
            )

            if record.get("is_directory"):

                events.append(
                    create_event(
                        timestamp=deletion_time,
                        artifact_type="mft",
                        event_type=EventType.DIRECTORY_DELETED,
                        category=EventCategory.FILESYSTEM,
                        object_name=object_name,
                        object_path=object_path,
                        description=f"Deleted directory: {record.get('primary_path')}",
                        source_file=record.get("source_path"),
                        evidence=dict(base_evidence),
                    )
                )

            else:

                events.append(
                    create_event(
                        timestamp=deletion_time,
                        artifact_type="mft",
                        event_type=EventType.FILE_DELETION,
                        category=EventCategory.FILESYSTEM,
                        object_name=object_name,
                        object_path=object_path,
                        description=f"Deleted file: {record.get('primary_path')}",
                        source_file=record.get("source_path"),
                        evidence=dict(base_evidence),
                    )
                )

        # --------------------------------------------------
        # Possible timestomping
        # --------------------------------------------------

        timestamp_mismatch = (
            timestamps_differ(record.get("si_created"), record.get("fn_created"))
            or timestamps_differ(record.get("si_modified"), record.get("fn_modified"))
        )

        if timestamp_mismatch:

            events.append(
                create_event(
                    timestamp=record.get("si_entry_modified")
                    or record.get("fn_entry_modified")
                    or record.get("si_modified"),
                    artifact_type="mft",
                    event_type=EventType.TIMESTAMP_INCONSISTENCY,
                    category=EventCategory.FILESYSTEM,
                    object_name=object_name,
                    object_path=object_path,
                    description=f"Possible timestamp manipulation detected on {record.get('primary_path')}",
                    source_file=record.get("source_path"),
                    evidence={
                        **base_evidence,
                        "si_created": record.get("si_created"),
                        "fn_created": record.get("fn_created"),
                        "si_modified": record.get("si_modified"),
                        "fn_modified": record.get("fn_modified"),
                        "si_accessed": record.get("si_accessed"),
                        "fn_accessed": record.get("fn_accessed"),
                        "si_entry_modified": record.get("si_entry_modified"),
                        "fn_entry_modified": record.get("fn_entry_modified"),
                    },
                )
            )


        return events