from io import BytesIO
from pathlib import Path

import olefile
from LnkParse3.lnk_file import LnkFile

from modules.parsers.base_parser import BaseParser
from modules.parsers.lnk.lnk_parser import LNKParser


class JumpListParser(BaseParser):
    """
    Parser des Jump Lists Windows
    (.automaticDestinations-ms / .customDestinations-ms).
    """

    def __init__(self):

        self.lnk_parser = LNKParser()

    def parse(self, artifact_path: Path) -> list[dict]:

        results = []
        try:
            # Custom Destinations are not necessarily OLE compound files.
            # This parser supports only the OLE-based automatic format.
            with artifact_path.open("rb") as source:
                if source.read(8) != olefile.MAGIC:
                    return []

            with olefile.OleFileIO(artifact_path) as ole:

                for stream in ole.listdir():

                    stream_name = stream[0]

                    # On ignore DestList pour la V1
                    if stream_name == "DestList":
                        continue

                    try:

                        data = ole.openstream(stream).read()

                        lnk = LnkFile(BytesIO(data))

                        lnk.process()

                        entry = self.lnk_parser._parse_lnk(

                            lnk,

                            f"{artifact_path.name}:{stream_name}",

                            str(artifact_path)

                        )   
                        if "lnk_name" in entry:
                            entry["entry_name"] = entry.pop("lnk_name")
                            
                        entry["artifact_type"] = "jumplist"

                        entry["jump_list_file"] = artifact_path.name

                        entry["stream_id"] = stream_name

                        try:
                            entry["entry_number"] = int(stream_name, 16)
                        except ValueError:
                            entry["entry_number"] = None  # Sécurité pour les chaînes non convertibles

                        results.append(entry)

                    except Exception:

                        continue

            return results
        except Exception as e:
            return self.handle_error(artifact_path, e)