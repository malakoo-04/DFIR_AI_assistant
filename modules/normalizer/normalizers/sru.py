from modules.models.event_category import EventCategory
from modules.models.event_type import EventType
from modules.normalizer.base_normalizer import BaseNormalizer
from modules.normalizer.event import create_event


class SRUNormalizer(BaseNormalizer):
    """Convert supported SRU accounting rows into behavior-focused events."""

    @staticmethod
    def _number(record, field, default=0):
        value = record.get(field)
        try:
            return int(value) if value is not None else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _identity(record):
        application_id = record.get("application_id", record.get("AppId"))
        application = record.get("application")
        if not application and application_id is not None:
            application = f"AppId:{application_id}"
        return application, application_id, record.get("user_sid"), record.get("user_id", record.get("UserId"))

    def _base_event(self, record, event_type, category, description, *, object_path=None):
        application, application_id, user_sid, user_id = self._identity(record)

        event = create_event(
            artifact_type="sru",
            event_type=event_type,
            category=category,
            timestamp=record.get("TimeStamp"),
            object_name=application,
            object_path=object_path or record.get("application_path"),
            user=user_sid,
            description=description,
            confidence=0.90,
            # No evidence dict here: table/record_id/database/application_id/
            # user_sid/source_file are all already first-class fields on this
            # event (see below and create_event's own params) — an evidence
            # dict would only duplicate them, not add anything self-contained
            # that isn't already there.
            source_file=record.get("source_path"),
            raw_data=record,
        )
        event.update({
            "application": application,
            "application_id": application_id,
            "user_sid": user_sid,
            "user_id": user_id,
            "record_id": record.get("record_id"),
            "table": record.get("table"),
            "database": record.get("database"),
            "database_format_version": record.get("database_format_version"),
            "timestamp_semantics": "sru_accounting_interval",
        })
        return event

    def _normalize_network_usage(self, record):
        bytes_sent = self._number(record, "BytesSent")
        bytes_received = self._number(record, "BytesRecvd")
        if bytes_sent == 0 and bytes_received == 0:
            return []

        event = self._base_event(
            record,
            EventType.APPLICATION_NETWORK_USAGE,
            EventCategory.NETWORK,
            "Application transferred network data during an SRU accounting interval",
        )
        event.update({
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "total_bytes": bytes_sent + bytes_received,
            "network_interface": record.get("InterfaceLuid"),
            "profile_id": record.get("L2ProfileId"),
            "profile_flags": record.get("L2ProfileFlags"),
        })
        return [event]

    def _normalize_resource_usage(self, record):
        foreground_cycles = self._number(record, "ForegroundCycleTime")
        background_cycles = self._number(record, "BackgroundCycleTime")
        foreground_read = self._number(record, "ForegroundBytesRead")
        background_read = self._number(record, "BackgroundBytesRead")
        foreground_written = self._number(record, "ForegroundBytesWritten")
        background_written = self._number(record, "BackgroundBytesWritten")

        event = self._base_event(
            record,
            EventType.APPLICATION_RESOURCE_USAGE,
            EventCategory.SYSTEM,
            "Application consumed CPU and disk resources during an SRU accounting interval",
        )
        event.update({
            # These are CPU cycles, not wall-clock CPU seconds.
            "foreground_cycle_time": foreground_cycles,
            "background_cycle_time": background_cycles,
            "total_cycle_time": foreground_cycles + background_cycles,
            "foreground_bytes_read": foreground_read,
            "background_bytes_read": background_read,
            "foreground_bytes_written": foreground_written,
            "background_bytes_written": background_written,
            "total_bytes_read": foreground_read + background_read,
            "total_bytes_written": foreground_written + background_written,
            "face_time": record.get("FaceTime"),
        })
        return [event]

    def _normalize_connectivity(self, record):
        event = self._base_event(
            record,
            EventType.NETWORK_CONNECTIVITY,
            EventCategory.NETWORK,
            "Network connectivity was recorded by SRU",
        )
        event.update({
            "network_interface": record.get("InterfaceLuid"),
            "profile_id": record.get("L2ProfileId"),
            "profile_flags": record.get("L2ProfileFlags"),
            "connected_time": record.get("ConnectedTime"),
            "connect_start_time": record.get("ConnectStartTime"),
        })
        return [event]

    def _normalize_energy_usage(self, record):
        # Only normalize a numeric energy measure. Several SRU energy tables
        # contain opaque binary blobs; preserving them raw is safer than guessing.
        energy = record.get("Energy")
        if not isinstance(energy, (int, float)):
            return []
        event = self._base_event(
            record,
            EventType.APPLICATION_ENERGY_USAGE,
            EventCategory.SYSTEM,
            "Application energy usage was recorded by SRU",
        )
        event["energy"] = energy
        return [event]

    def normalize(self, record: dict) -> list[dict]:
        # Field-based routing remains valid across Windows versions and avoids
        # guessing semantics from undocumented SRU table GUIDs.
        if "BytesSent" in record and "BytesRecvd" in record:
            return self._normalize_network_usage(record)
        if "ForegroundCycleTime" in record and "BackgroundCycleTime" in record:
            return self._normalize_resource_usage(record)
        if "ConnectedTime" in record and "ConnectStartTime" in record:
            return self._normalize_connectivity(record)
        if "Energy" in record:
            return self._normalize_energy_usage(record)
        return []