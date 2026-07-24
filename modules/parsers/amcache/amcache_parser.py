from pathlib import Path

from yarp import Registry

from modules.parsers.base_parser import BaseParser


class AmcacheParser(BaseParser):
    """
    Parser générique de Amcache.hve.

    Extrait automatiquement toutes les catégories,
    toutes les entrées et toutes leurs valeurs.
    """

    def parse(self, artifact_path: Path) -> list[dict]:

        results = []

        with artifact_path.open("rb") as f:

            hive = Registry.RegistryHive(f)

            root = hive.root_key().subkey("Root")

            for category in root.subkeys():

                results.extend(

                    self._parse_category(

                        category,

                        artifact_path

                    )

                )

        return results

    def _parse_category(self, category, artifact_path):

        category_results = []

        for entry in category.subkeys():

            record = {

                "artifact_type": "amcache",

                "category": category.name(),

                "entry_name": entry.name(),

                "entry_path": entry.path(),

                "last_written": entry.last_written_timestamp(),

                "source_path": str(artifact_path)

            }
            for value in entry.values():

                record[value.name()] = self._read_value(value)

            category_results.append(record)

        return category_results
    
    def _read_value(self, value):

        try:

            data = value.data()

            if isinstance(data, str):
                return data.rstrip("\x00")

            if isinstance(data, bytes):

                try:
                    return data.decode("utf-16le").rstrip("\x00")
                except Exception:
                    pass

                try:
                    return data.decode("utf-8").rstrip("\x00")
                except Exception:
                    pass

                return data.hex()

            return data

        except Exception:
            return None