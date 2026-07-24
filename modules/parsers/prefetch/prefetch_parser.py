from pathlib import Path

from windowsprefetch import Prefetch

from modules.parsers.base_parser import BaseParser


class PrefetchParser(BaseParser):
    """
    Parser des fichiers Windows Prefetch (.pf).
    """

    def parse(self, artifact_path: Path) -> list[dict]:
        try:
            pf = Prefetch(str(artifact_path))
        except Exception as e:
            print(f"[PREFETCH ERROR] {artifact_path}")
            print(e)
            return []

        def safe(attr, default=None):
            try:
                return getattr(pf, attr)
            except Exception as e:
                print(f"[PREFETCH WARN] {artifact_path}: missing '{attr}' ({e})")
                return default

        resources = safe("resources", []) or []
        loaded_files = sorted(set(resources))
       # print(vars(pf))

        timestamps = safe("timestamps", []) or []
        """print(type(timestamps))
        if timestamps:
            print(type(timestamps[0]))
            print(timestamps[0])

        print(timestamps)"""
        volumes = safe("volumesInformationArray", []) or []

        return [{
            "artifact_type": "prefetch",
            "filename": safe("executableName", artifact_path.stem),
            "source_path": str(artifact_path),
            "prefetch_version": safe("version"),
            "prefetch_hash": safe("hash"),
            "run_count": safe("runCount"),
            "last_run_times": timestamps,
            "execution_slots": len(timestamps),
            "loaded_files": loaded_files,
            "loaded_files_count": len(loaded_files),
            "volumes": volumes,
            "volumes_count": len(volumes),
    }]