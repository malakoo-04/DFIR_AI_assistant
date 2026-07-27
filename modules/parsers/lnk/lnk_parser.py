from pathlib import Path

from LnkParse3.lnk_file import LnkFile

from modules.parsers.base_parser import BaseParser


class LNKParser(BaseParser):
    """
    Parser des raccourcis Windows (.lnk) utilisant LnkParse3.
    """

    def _safe_call(self, func):
        """
        Exécute une fonction en toute sécurité.
        """

        try:

            result = func()

            if callable(result):
                result = result()

            return result

        except Exception:

            return None

    def _parse_lnk(self, lnk: LnkFile, source_name: str, source_path: str) -> dict:
        """
        Parse un objet LnkFile déjà chargé.
        Cette méthode pourra être réutilisée par le JumpListParser.
        """

        return {

            "artifact_type": "lnk",

            "lnk_name": source_name,

            "source_path": source_path,

            # Cible
            "target_path": self._safe_call(lambda: lnk.info.local_base_path),
            "relative_path": self._safe_call(lambda: lnk.string_data.relative_path),
            "working_directory": self._safe_call(lambda: lnk.string_data.working_directory),

            # Informations utilisateur
            "description": self._safe_call(lambda: lnk.string_data.description),
            "command_line_arguments": self._safe_call(lambda: lnk.string_data.command_line_arguments),
            "icon_location": self._safe_call(lambda: lnk.string_data.icon_location),

            # Métadonnées
            "creation_time": self._safe_call(lambda: lnk.header.creation_time),
            "modified_time": self._safe_call(lambda: lnk.header.write_time),
            "access_time": self._safe_call(lambda: lnk.header.access_time),
            "file_size": self._safe_call(lambda: lnk.header.file_size),

            # Volume
            "drive_serial": self._safe_call(lambda: lnk.info.drive_serial_number),
            "drive_type": self._safe_call(lambda: lnk.info.drive_type),
            "volume_label": self._safe_call(lambda: lnk.info.volume_label),

        }

    def parse(self, artifact_path: Path) -> list[dict]:

        with artifact_path.open("rb") as f:

            lnk = LnkFile(f)

            lnk.process()

            return [

                self._parse_lnk(

                    lnk,

                    artifact_path.name,

                    str(artifact_path)

                )

            ]