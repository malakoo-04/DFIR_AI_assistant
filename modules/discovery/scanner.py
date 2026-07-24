from pathlib import Path
from datetime import datetime
from collections import Counter
import json
from .artifact import Artifact
from .signatures import SIGNATURES


class DiscoveryEngine:
    """
    Parcourt récursivement un dossier KAPE/FastIR
    et identifie automatiquement les artefacts connus.
    """

    def __init__(self, root_path: str | Path):

        self.root_path = Path(root_path)

        # Artefacts reconnus
        self.artifacts = []

        self.known_unsupported = []

        # Fichiers inconnus
        self.unknown_files = []

        # Statistiques
        self.total_files = 0
        self.signature_counter = Counter()
        self.extension_counter = Counter()

    def scan(self) -> list[Artifact]:

        self.artifacts.clear()
        self.unknown_files.clear()

        self.total_files = 0
        self.signature_counter.clear()
        self.extension_counter.clear()

        for file in self.root_path.rglob("*"):

            if not file.is_file():
                continue

            self.total_files += 1

            artifact = self._identify(file)

            if artifact:

                self.artifacts.append(artifact)

                self.signature_counter[
                    artifact.artifact_type.value
                ] += 1

            else:

                self.unknown_files.append(file)

                extension = file.suffix.lower()

                if extension == "":
                    extension = "<no_extension>"

                self.extension_counter[extension] += 1

        self._print_summary()

        return self.artifacts

    def _identify(self, file: Path) -> Artifact | None:

        for signature in SIGNATURES:

            if not signature.enabled:
                continue

            if signature.matches(file):

                stat = file.stat()

                return Artifact(

                    name=file.name,

                    path=file,

                    artifact_type=signature.artifact_type,

                    size=stat.st_size,

                    created=datetime.fromtimestamp(stat.st_ctime),

                    modified=datetime.fromtimestamp(stat.st_mtime),

                    accessed=datetime.fromtimestamp(stat.st_atime),

                    description=signature.description

                )

        return None

    def _print_summary(self):

        print("\n")
        print("=" * 60)
        print("DISCOVERY SUMMARY".center(60))
        print("=" * 60)

        print(f"Total files scanned : {self.total_files}")
        print(f"Recognized artifacts: {len(self.artifacts)}")
        print(f"Ignored files       : {len(self.unknown_files)}")

        print("\nArtifacts by type")
        print("-" * 60)

        for artifact_type, count in sorted(self.signature_counter.items()):

            print(f"{artifact_type:<25} {count}")

        print("\nUnknown extensions")
        print("-" * 60)

        for ext, count in sorted(
                self.extension_counter.items(),
                key=lambda x: x[1],
                reverse=True):

            print(f"{ext:<25} {count}")

        print("\nUnknown files")
        print("-" * 60)

        for file in self.unknown_files:

            print(file)

        print("=" * 60)

    def export_unknown_inventory(self, output_path):

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = []

        for file in self.unknown_files:

            stat = file.stat()

            data.append({
                "name": file.name,
                "path": str(file),
                "extension": file.suffix.lower() or "<no_extension>",
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
            })

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        print(f"\nUnknown inventory exported to {output_path}")