from pathlib import Path

from dfir_ntfs import Attributes
from dfir_ntfs import USN

from modules.parsers.base_parser import BaseParser


class USNParser(BaseParser):
    """
    Parser du journal NTFS USN ($J).
    """

    def parse(self, artifact_path: Path) -> list[dict]:

        results = []

        with artifact_path.open("rb") as f:

            parser = USN.ChangeJournalParser(f)

            for record in parser.usn_records():

                reason_code = record.get_reason()

                source_code = record.get_source_info()

                attributes_code = record.get_file_attributes()

                entry = {

                    "artifact_type": "usn",

                    "source_path": str(artifact_path),

                    "usn": record.get_usn(),

                    "timestamp": record.get_timestamp(),

                    "file_name": record.get_file_name(),

                    "frn":
                        record.get_file_reference_number(),

                    "parent_frn":
                        record.get_parent_file_reference_number(),

                    # Reason
                    "reason_code": reason_code,

                    "reason":
                        USN.ResolveReasonCodes(reason_code),

                    # File Attributes
                    "file_attributes_code": attributes_code,

                    "file_attributes":
                        Attributes.ResolveFileAttributes(attributes_code),

                    # Source Info
                    "source_info_code": source_code,

                    "source_info":
                        USN.ResolveSourceCodes(source_code),

                    "security_id":
                        record.get_security_id(),

                    "usn_version_major":
                        record.get_major_version(),

                    "usn_version_minor":
                        record.get_minor_version(),

                    "record_type": "change_journal"

                }

                results.append(entry)

        return results