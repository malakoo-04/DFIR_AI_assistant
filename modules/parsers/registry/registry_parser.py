from pathlib import Path
from yarp import Registry
from modules.parsers.base_parser import BaseParser
from datetime import timezone

class RegistryParser(BaseParser):
    """
    Parser des ruches Registry Windows utilisant YARP.
    """

    def parse(self, artifact_path: Path) -> list[dict]:
        # 1 & 2. Extraction des métadonnées de la ruche au début
        hive_name = artifact_path.name
        hive_path = str(artifact_path)
        user = self._extract_user(artifact_path)
        results = []

        # Utilisation d'un context manager pour maintenir le fichier ouvert pendant le parcours
        with artifact_path.open("rb") as f:
            hive = Registry.RegistryHive(f)
            root = hive.root_key()
            
            if root:
                # On initialise le parcours ; la racine n'a pas de parent (None)
                self._walk_keys(
                    root,
                    results,
                    hive_name,
                    hive_path,
                    parent_path=None,
                    user=user,
                )

        return results

    @staticmethod
    def _extract_user(artifact_path: Path) -> str | None:
        """Return the profile name when a hive belongs to C:\\Users\\<profile>."""
        parts = artifact_path.parts
        for index, part in enumerate(parts[:-1]):
            if part.lower() == "users" and index + 1 < len(parts):
                return parts[index + 1]
        return None

    def _walk_keys(self, key, results, hive_name, hive_path, parent_path=None, user=None):
        # dfir_ntfs/LnkParse3/TimeUtils all hand normalizers a native tz-aware
        # datetime; YARP does the same here, so we keep it as-is instead of
        # stringifying it. Called once and cached, instead of twice, since
        # last_written_timestamp() isn't guaranteed to be a cheap accessor.
        last_written = key.last_written_timestamp()
        if last_written is not None:
              last_written = last_written.replace(tzinfo=timezone.utc)

        entry = {
            "hive": hive_name,          # 1. Nom de la ruche (ex: NTUSER.DAT)
            "user": user,
            "source_path": hive_path,    # 2. Chemin complet d'origine
            "artifact_type": "registry",
            "key_name": key.name(),
            "key_path": key.path(),
            "parent_key": parent_path,  # 5. Chemin de la clé parente (géré par récursion)
            "last_written": last_written,
            "subkeys_count": key.subkeys_count(),
            "values_count": key.values_count(),
            "values": []
        }

        for value in key.values():
            try:
                # 3. Récupération de l'ID numérique via la méthode officielle YARP (type_raw)
                type_id = value.type_raw() if hasattr(value, "type_raw") else None

                entry["values"].append({
                    "name": value.name(),
                    "type": str(value.type_str()),
                    "type_id": type_id,        # 3. Type ID numérique préservé
                    "value_data": value.data(),  # 4. Données brutes (bytes, list, etc.) pour le Normalizer
                    
                })
            except Exception:
                entry["values"].append({
                    "name": "<error>",
                    "type": "<unknown>",
                    "type_id": None,
                    "value_data": "<unable to parse>"
                })

        results.append(entry)

        # On capture le chemin actuel pour le transmettre en tant que parent aux enfants
        current_path = key.path()
        for subkey in key.subkeys():
            self._walk_keys(
                subkey,
                results,
                hive_name,
                hive_path,
                parent_path=current_path,
                user=user,
            )