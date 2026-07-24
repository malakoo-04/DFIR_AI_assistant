from modules.normalizer.base_normalizer import BaseNormalizer
from modules.normalizer.event import create_event
import codecs
import re
import os
from modules.models.event_type import EventType
from modules.models.event_category import EventCategory

class RegistryNormalizer(BaseNormalizer):

    def normalize(self, record: dict) -> list[dict]:

        path = record.get("key_path", "").lower()

        if "\\currentversion\\runonce" in path:
                return self._normalize_run(record)

        if "\\currentversion\\run" in path:
                return self._normalize_run(record)
        

        if "\\services" in path:
                return self._normalize_services(record)
        
        if "\\userassist" in path:
            return self._normalize_userassist(record)
        
        

        if "\\usbstor" in path:
            return self._normalize_usbstor(record)

        if "\\recentdocs" in path:
            return self._normalize_recentdocs(record)

        return []
    
    def _normalize_run(self, record: dict) -> list[dict]:

        events = []

        values = record.get("values", [])

        for value in values:

            event = create_event(

                artifact_type="registry",

                event_type=EventType.PERSISTENCE,

                category=EventCategory.PERSISTENCE,

                timestamp=record.get("last_written"),

                object_name=value.get("name") or "(Default)",

                object_path=value.get("value_data"),

                related_objects=[],

                description=f"Registry Run key: {value.get('name')}",

                confidence=0.95,

                evidence={
                    "key_path": record.get("key_path"),
                },

                source_file=record.get("source_path"),

                raw_data=record,

            )

            events.append(event)


        return events
    
    def _normalize_services(self, record: dict) -> list[dict]:

        events = []
        values = record.get("values", [])
        start_type=None
        image_path = None
        START_TYPES = {
            0: "Boot",
            1: "System",
            2: "Automatic",
            3: "Manual",
            4: "Disabled"
        }
        display_name = None

        for value in values:

            name = value.get("name")

            if name == "ImagePath":
                image_path = value.get("value_data")

            elif name == "Start":
                start_type = value.get("value_data")

            elif name == "DisplayName":
                display_name = value.get("value_data")

        if isinstance(image_path, bytes):
            try:
                image_path = image_path.decode("utf-16le").rstrip("\x00")
            except Exception:
                image_path = str(image_path)

        if image_path is None:
            return []

        event = create_event(

            artifact_type="registry",

            event_type=EventType.SERVICE_CREATED,

            category=EventCategory.PERSISTENCE,

            timestamp=record.get("last_written"),

            object_name=display_name or record.get("key_name"),

            object_path=image_path,

            related_objects=[],

            description=(
                    f"Windows service "
                    f"'{display_name or record.get('key_name')}' "
                    f"configured to start from "
                    f"{image_path}"
                ),

            confidence=0.95,

            evidence={
                "key_path": record.get("key_path"),
                "service_name": display_name or record.get("key_name"),
                "image_path": image_path,
            },

            source_file=record.get("source_path"),

            raw_data=record,

        )

        event["start_type"] = START_TYPES.get(start_type, "Unknown")

        events.append(event)
       

        return events
    
    def _normalize_userassist(self, record: dict) -> list[dict]:

        events = []

        values = record.get("values", [])

        for value in values:
            # Skip non-binary values (Version, etc.)
            if value.get("type") != "REG_BINARY":
                continue

            encoded_name = value.get("name", "")

            # Decode the UserAssist name
            decoded_name = codecs.decode(encoded_name, "rot_13")

            # Skip internal UserAssist metadata
            if decoded_name.startswith("UEME_"):
                continue

            event = create_event(

                artifact_type="registry",

                event_type=EventType.PROCESS_EXECUTION,

                category=EventCategory.EXECUTION,

                timestamp=record.get("last_written"),

                object_name=decoded_name,

                object_path=None,

                related_objects=[],

                description=f"UserAssist execution: {decoded_name}",

                confidence=0.90,
                
                evidence={
                    "key_path": record.get("key_path"),
                    "encoded_name": encoded_name,
                    "decoded_name": decoded_name,
                },

                source_file=record.get("source_path"),

                raw_data=record,

            )

            events.append(event)
        return events
    
    @staticmethod
    def _registry_text(value):
        if value is None:
            return None
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-16le")
            except UnicodeDecodeError:
                value = value.decode("utf-8", errors="replace")
        return str(value).rstrip("\x00")

    @staticmethod
    def _usbstor_identity(device_key):
        match = re.match(
            r"^Disk&Ven_(?P<vendor>[^&]+)&Prod_(?P<product>[^&]+)&Rev_(?P<revision>.+)$",
            device_key,
            re.IGNORECASE,
        )
        if not match:
            return None
        return {name: value.replace("_", " ").strip() for name, value in match.groupdict().items()}

    def _normalize_usbstor(self, record):
        """Create one USB device-history event for an Enum\\USBSTOR serial instance."""
        key_path = record.get("key_path", "")
        parts = [part for part in key_path.replace("/", "\\").split("\\") if part]
        lower_parts = [part.lower() for part in parts]
        try:
            usb_index = lower_parts.index("usbstor")
        except ValueError:
            return []

        # Exclude Control\\USBSTOR and DriverDatabase entries: they are not devices.
        if usb_index < 1 or lower_parts[usb_index - 1] != "enum" or len(parts) != usb_index + 3:
            return []
        identity = self._usbstor_identity(parts[usb_index + 1])
        if not identity:
            return []

        serial_number = parts[usb_index + 2]
        values = {
            str(value.get("name", "")).lower(): self._registry_text(value.get("value_data"))
            for value in record.get("values", [])
        }
        friendly_name = values.get("friendlyname")
        event = create_event(
            artifact_type="registry",
            event_type=EventType.USB_DEVICE_CONNECTED,
            category=EventCategory.DEVICE,
            timestamp=record.get("last_written"),
            object_name=friendly_name or f"{identity['vendor']} {identity['product']}",
            description=f"USB storage device history: {identity['vendor']} {identity['product']} ({serial_number})",
            confidence=0.95,
            evidence={
                "hive": record.get("hive"),
                "key_path": key_path,
            },
            source_file=record.get("source_path"),
            raw_data=record,
        )
        event.update({
            **identity,
            "serial_number": serial_number,
            "device_instance_id": f"{parts[usb_index + 1]}\\{serial_number}",
            "friendly_name": friendly_name,
            "parent_id_prefix": values.get("parentidprefix"),
            "container_id": values.get("containerid"),
            "class_guid": values.get("classguid"),
            "service": values.get("service"),
            "timestamp_semantics": "registry_key_last_written",
        })
        return [event]
    
    _RECENTDOCS_EXTENSIONS = (
        "exe", "lnk", "txt", "csv", "log", "pdf", "doc", "docx", "xls",
        "xlsx", "ppt", "pptx", "zip", "rar", "7z", "msi", "ps1", "bat",
        "cmd", "py", "js", "vbs", "json", "xml", "yml", "yaml", "dll",
        "sys", "conf", "config", "ini", "reg", "evtx", "sqlite", "db-wal",
        "db-shm", "db",
    )
    _RECENTDOCS_PATH_RE = re.compile(
        r"([A-Za-z]:\\[^\x00\r\n]+?\.(?:" + "|".join(_RECENTDOCS_EXTENSIONS) + r"))$",
        re.IGNORECASE,
    )
    _RECENTDOCS_NAME_RE = re.compile(
        r"([^\\/\x00\r\n]+?\.(?:" + "|".join(_RECENTDOCS_EXTENSIONS) + r"))$",
        re.IGNORECASE,
    )
    _RECENTDOCS_IGNORED_NAMES = {"thumbs.db", "desktop.ini"}

    @staticmethod
    def _recentdocs_bytes(value_data):
        """Accept parser bytes and JSON-exported hexadecimal values safely."""
        if isinstance(value_data, bytes):
            return value_data
        if isinstance(value_data, bytearray):
            return bytes(value_data)
        if isinstance(value_data, str):
            compact = value_data.strip()
            if len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
                try:
                    return bytes.fromhex(compact)
                except ValueError:
                    pass
        return None

    @classmethod
    def _extract_recentdocs_document(cls, value_data):
        """Extract one clean filename/path without joining binary registry fields."""
        raw = cls._recentdocs_bytes(value_data)
        if not raw:
            return None

        text = raw.decode("utf-16le", errors="ignore")
        strings = [item.strip() for item in text.split("\x00") if item.strip()]

        candidates = []
        for item in strings:
            match = cls._RECENTDOCS_PATH_RE.search(item)
            if match:
                candidates.append((100, match.group(1)))

        for item in strings:
            match = cls._RECENTDOCS_NAME_RE.search(item)
            if match and match.group(1).isprintable():
                candidates.append((50, match.group(1)))

        filtered = []
        for score, candidate in candidates:
            filename = os.path.basename(candidate).lower()
            if filename.startswith("~$") or filename in cls._RECENTDOCS_IGNORED_NAMES:
                continue
            filtered.append((score, -len(candidate), candidate))
        if filtered:
            return max(filtered)[2]

        return None

    def _normalize_recentdocs(self, record):
        """Normalize only user-hive RecentDocs values into bounded evidence."""
        hive = str(record.get("hive", "")).lower()
        if hive not in {"ntuser.dat", "usrclass.dat"}:
            return []

        events = []
        timestamp = record.get("last_written")
        key_path = record.get("key_path", "")
        user = record.get("user")

        for value in record.get("values", []):
            name = str(value.get("name", ""))
            # ViewStream/configuration values are not MRU entries. Real RecentDocs
            # entries use numeric value names; MRUListEx only defines their order.
            if not name.isdecimal() or value.get("type") != "REG_BINARY":
                continue

            document = self._extract_recentdocs_document(value.get("value_data"))
            if not document:
                continue

            event = create_event(
                artifact_type="registry",
                event_type=EventType.DOCUMENT_OPENED,
                category=EventCategory.USER_ACTIVITY,
                timestamp=timestamp,
                object_name=os.path.basename(document),
                object_path=document,
                user=user,
                description=f"RecentDocs reference: {document}",
                # A key LastWrite is supporting evidence, not a per-item open time.
                confidence=0.65,
                evidence={
                    "hive": record.get("hive"),
                    "key_path":key_path,
                    "value_name": name,
                },
                source_file=record.get("source_path"),
                raw_data=record,
            )
            event.update({
                "document": os.path.basename(document),
                "document_path": document,
                "registry_key": key_path,
                "registry_value": name,
                "timestamp_semantics": "registry_key_last_written",
            })
            events.append(event)

        return events