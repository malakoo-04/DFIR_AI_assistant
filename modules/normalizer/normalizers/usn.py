from modules.models.event_category import EventCategory
from modules.models.event_type import EventType
from modules.normalizer.base_normalizer import BaseNormalizer
from modules.normalizer.event import create_event


class USNNormalizer(BaseNormalizer):
    """
    Normalize high-value NTFS USN Journal operations into timeline events.

    A USN record timestamp represents the filesystem operation itself.
    Full file paths cannot be reconstructed from USN alone, therefore
    FRNs are preserved for later MFT correlation.
    """

    # ----------------------------
    # USN reason flags
    # ----------------------------

    DATA_OVERWRITE = 0x00000001
    DATA_EXTEND = 0x00000002
    DATA_TRUNCATION = 0x00000004

    NAMED_DATA_OVERWRITE = 0x00000010
    NAMED_DATA_EXTEND = 0x00000020
    NAMED_DATA_TRUNCATION = 0x00000040

    FILE_CREATE = 0x00000100
    FILE_DELETE = 0x00000200

    EA_CHANGE = 0x00000400
    SECURITY_CHANGE = 0x00000800

    RENAME_OLD_NAME = 0x00001000
    RENAME_NEW_NAME = 0x00002000

    INDEXABLE_CHANGE = 0x00004000
    BASIC_INFO_CHANGE = 0x00008000
    HARD_LINK_CHANGE = 0x00010000
    COMPRESSION_CHANGE = 0x00020000
    ENCRYPTION_CHANGE = 0x00040000
    OBJECT_ID_CHANGE = 0x00080000
    REPARSE_POINT_CHANGE = 0x00100000
    STREAM_CHANGE = 0x00200000
    TRANSACTED_CHANGE = 0x00400000
    CLOSE = 0x80000000

    DIRECTORY_ATTRIBUTE = 0x00000010

    IGNORED_NAMES = {
        "thumbs.db",
        "desktop.ini",
    }

    REASON_FLAGS = {
        DATA_OVERWRITE: "DATA_OVERWRITE",
        DATA_EXTEND: "DATA_EXTEND",
        DATA_TRUNCATION: "DATA_TRUNCATION",
        NAMED_DATA_OVERWRITE: "NAMED_DATA_OVERWRITE",
        NAMED_DATA_EXTEND: "NAMED_DATA_EXTEND",
        NAMED_DATA_TRUNCATION: "NAMED_DATA_TRUNCATION",
        FILE_CREATE: "FILE_CREATE",
        FILE_DELETE: "FILE_DELETE",
        EA_CHANGE: "EA_CHANGE",
        SECURITY_CHANGE: "SECURITY_CHANGE",
        RENAME_OLD_NAME: "RENAME_OLD_NAME",
        RENAME_NEW_NAME: "RENAME_NEW_NAME",
        INDEXABLE_CHANGE: "INDEXABLE_CHANGE",
        BASIC_INFO_CHANGE: "BASIC_INFO_CHANGE",
        HARD_LINK_CHANGE: "HARD_LINK_CHANGE",
        COMPRESSION_CHANGE: "COMPRESSION_CHANGE",
        ENCRYPTION_CHANGE: "ENCRYPTION_CHANGE",
        OBJECT_ID_CHANGE: "OBJECT_ID_CHANGE",
        REPARSE_POINT_CHANGE: "REPARSE_POINT_CHANGE",
        STREAM_CHANGE: "STREAM_CHANGE",
        TRANSACTED_CHANGE: "TRANSACTED_CHANGE",
        CLOSE: "CLOSE",
    }

    DATA_CHANGE = (
        DATA_OVERWRITE
        | DATA_EXTEND
        | DATA_TRUNCATION
        | NAMED_DATA_OVERWRITE
        | NAMED_DATA_EXTEND
        | NAMED_DATA_TRUNCATION
    )

    @classmethod
    def _decode_reason_flags(cls, reason_code):
        try:
            reason_code = int(reason_code)
        except (TypeError, ValueError):
            return []

        return [
            name
            for value, name in cls.REASON_FLAGS.items()
            if reason_code & value
        ]

    @classmethod
    def _classify_operation(cls, reason_code):
        try:
            reason_code = int(reason_code)
        except (TypeError, ValueError):
            return None

        if reason_code & cls.FILE_CREATE:
            return EventType.FILE_CREATION, "created", True

        if reason_code & cls.FILE_DELETE:
            return EventType.FILE_DELETION, "deleted", True

        if reason_code & cls.RENAME_NEW_NAME:
            return EventType.FILE_RENAMED, "renamed", True

        if reason_code & cls.DATA_CHANGE:
            # Preserve a compact modification record for correlation, but do
            # not place every write/extend/truncate into the main timeline.
            return EventType.FILE_MODIFICATION, "modified", False

        return None

    @classmethod
    def _is_noise(cls, record):
        filename = str(record.get("file_name") or "").strip()

        if not filename:
            return True

        lowered = filename.lower()

        if lowered in cls.IGNORED_NAMES:
            return True

        attributes = record.get("file_attributes_code") or 0

        try:
            is_directory = bool(int(attributes) & cls.DIRECTORY_ATTRIBUTE)
        except (TypeError, ValueError):
            is_directory = (
                "DIRECTORY"
                in str(record.get("file_attributes", "")).upper()
            )

        if is_directory:
            return True

        if lowered.startswith("~$"):
            return True

        return False

    def normalize(self, record):

        if self._is_noise(record):
            return []

        operation = self._classify_operation(record.get("reason_code"))

        if operation is None:
            return []

        event_type, operation_name, timeline_eligible = operation

        filename = record.get("file_name")
        frn = record.get("frn")
        parent_frn = record.get("parent_frn")

        reason_flags = self._decode_reason_flags(
            record.get("reason_code")
        )

        event = create_event(
            artifact_type="usn",
            event_type=event_type,
            category=EventCategory.FILESYSTEM,
            timestamp=record.get("timestamp"),
            object_name=filename,
            object_path=None,
            related_objects=[
                x
                for x in (
                    f"frn:{frn}" if frn else None,
                    f"parent_frn:{parent_frn}" if parent_frn else None,
                )
                if x
            ],
            description=f"USN Journal: file {operation_name}: {filename}",
            confidence=0.95,
            # No evidence dict: usn/frn/reason/source are all already
            # first-class fields on this event via event.update() and
            # source_file below — see USN's docstring, same reasoning as SRU.
            source_file=record.get("source_path"),
            raw_data=record,
        )

        event.update({
            "file_name": filename,
            "file_reference": frn,
            "parent_reference": parent_frn,
            "usn": record.get("usn"),
            "reason": record.get("reason"),
            "reason_code": record.get("reason_code"),
            "reason_flags": reason_flags,
            "file_attributes": record.get("file_attributes"),
            "file_attributes_code": record.get("file_attributes_code"),
            "source_info": record.get("source_info"),
            "source_info_code": record.get("source_info_code"),
            "security_id": record.get("security_id"),
            "usn_version": (
                f"{record.get('usn_version_major')}."
                f"{record.get('usn_version_minor')}"
            ),
            "timestamp_semantics": "usn_record_timestamp",
            "timeline_eligible": timeline_eligible,
        })

        return [event]