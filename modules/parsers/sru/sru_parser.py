from datetime import datetime, timedelta
from pathlib import Path
import struct

import pyesedb

from modules.parsers.base_parser import BaseParser
from modules.utils.time_utils import TimeUtils


class SRUParser(BaseParser):
    """Extract factual rows from SRUDB.dat without assigning behavior."""

    _ID_MAP_TABLE = "SruDbIdMapTable"
    _FILETIME_COLUMNS = {"EndTime", "StartTime", "ConnectStartTime", "EventTimestamp"}
    _OLE_AUTOMATION_EPOCH = datetime(1899, 12, 30)

    def parse(self, artifact_path: Path) -> list[dict]:
        db = pyesedb.file()
        db.open(str(artifact_path))
        try:
            tables = {
                db.get_table(index).get_name(): db.get_table(index)
                for index in range(db.get_number_of_tables())
            }
            id_map = self._build_id_map(tables.get(self._ID_MAP_TABLE))
            database_format_version = db.get_format_version()
            results = []

            for table_name, table in tables.items():
                if table_name.startswith("MSys") or table_name == self._ID_MAP_TABLE:
                    continue
                results.extend(
                    self._parse_table(
                        table,
                        table_name,
                        artifact_path,
                        id_map,
                        database_format_version,
                    )
                )
            return results
        finally:
            db.close()

    def _parse_table(self, table, table_name, artifact_path, id_map, database_format_version):
        table_results = []
        for record_index in range(table.get_number_of_records()):
            record = table.get_record(record_index)
            entry = {
                "artifact_type": "sru",
                "table": table_name,
                "source_path": str(artifact_path),
                "database": artifact_path.name,
                "database_format_version": database_format_version,
            }
            for column_index in range(record.get_number_of_values()):
                column_name = record.get_column_name(column_index)
                entry[column_name] = self._read_value(record, column_index, column_name)

            entry["record_id"] = entry.get("AutoIncId")
            self._enrich_identifier_fields(entry, id_map)
            table_results.append(entry)
        return table_results

    def _build_id_map(self, table):
        """Resolve SRU's AppId/UserId indexes while retaining the original IDs."""
        if table is None:
            return {}

        id_map = {}
        for record_index in range(table.get_number_of_records()):
            record = table.get_record(record_index)
            values = {
                record.get_column_name(index): self._read_value(
                    record, index, record.get_column_name(index)
                )
                for index in range(record.get_number_of_values())
            }
            identifier = values.get("IdIndex")
            if identifier is None:
                continue
            id_map[identifier] = {
                "type": values.get("IdType"),
                "value": self._decode_identifier(values.get("IdType"), values.get("IdBlob")),
            }
        return id_map

    @staticmethod
    def _decode_identifier(identifier_type, value):
        if not value:
            return None
        if identifier_type == 3 and isinstance(value, bytes):
            return SRUParser._sid_from_bytes(value)
        if identifier_type in {0, 1, 2} and isinstance(value, bytes):
            return value.decode("utf-16le", errors="replace").rstrip("\x00")
        return value

    @staticmethod
    def _sid_from_bytes(value):
        if len(value) < 8:
            return None
        revision, subauthority_count = value[0], value[1]
        if len(value) < 8 + subauthority_count * 4:
            return None
        authority = int.from_bytes(value[2:8], byteorder="big")
        subauthorities = [
            str(int.from_bytes(value[offset:offset + 4], byteorder="little"))
            for offset in range(8, 8 + subauthority_count * 4, 4)
        ]
        return "-".join([f"S-{revision}-{authority}", *subauthorities])

    @staticmethod
    def _application_name(value):
        """Extract the executable part of SRU's !!app.exe!timestamp!hash! form."""
        if not isinstance(value, str):
            return value
        if value.startswith("!!"):
            parts = value.split("!")
            if len(parts) > 2 and parts[2]:
                return parts[2]
        return value

    def _enrich_identifier_fields(self, entry, id_map):
        app_id = entry.get("AppId")
        user_id = entry.get("UserId")
        app = id_map.get(app_id, {})
        user = id_map.get(user_id, {})

        entry["application_id"] = app_id
        entry["application"] = self._application_name(app.get("value"))
        entry["application_path"] = (
            app.get("value")
            if isinstance(app.get("value"), str) and len(app["value"]) > 2 and app["value"][1:3] == ":\\"
            else None
        )
        entry["user_id"] = user_id
        entry["user_sid"] = user.get("value") if user.get("type") == 3 else None

    def _read_value(self, record, index, column_name):
        try:
            column_type = record.get_column_type(index)
        except Exception:
            return None

        try:
            if column_type == pyesedb.column_types.DATE_TIME:
                raw = record.get_value_data(index)
                if raw is None or len(raw) != 8:
                    return None
                return self._OLE_AUTOMATION_EPOCH + timedelta(days=struct.unpack("<d", raw)[0])

            if column_name in self._FILETIME_COLUMNS:
                value = record.get_value_data_as_integer(index)
                return TimeUtils.filetime_to_datetime(value)

            if column_type in {pyesedb.column_types.TEXT, pyesedb.column_types.LARGE_TEXT}:
                return record.get_value_data_as_string(index)
            if column_type == pyesedb.column_types.BOOLEAN:
                return record.get_value_data_as_boolean(index)
            if column_type in {pyesedb.column_types.FLOAT_32BIT, pyesedb.column_types.DOUBLE_64BIT}:
                return record.get_value_data_as_floating_point(index)
            if column_type in {
                pyesedb.column_types.INTEGER_8BIT_UNSIGNED,
                pyesedb.column_types.INTEGER_16BIT_SIGNED,
                pyesedb.column_types.INTEGER_16BIT_UNSIGNED,
                pyesedb.column_types.INTEGER_32BIT_SIGNED,
                pyesedb.column_types.INTEGER_32BIT_UNSIGNED,
                pyesedb.column_types.INTEGER_64BIT_SIGNED,
                pyesedb.column_types.CURRENCY,
            }:
                return record.get_value_data_as_integer(index)
            return record.get_value_data(index)
        except Exception:
            return None
