import json

from pathlib import Path
from collections import Counter
from .artifact import Artifact


class Inventory:

    def __init__(self):

        self.artifacts: list[Artifact] = []

    def add(self, artifact: Artifact):

        self.artifacts.append(artifact)

    def extend(self, artifacts: list[Artifact]):

        self.artifacts.extend(artifacts)

    def count(self):

        return len(self.artifacts)

    def export_json(self, output_file: str | Path):

        output = []

        for artifact in self.artifacts:

            output.append({

                "name": artifact.name,

                "path": str(artifact.path),

                "type": artifact.artifact_type.value,

                #"parser": artifact.parser,

                "size": artifact.size,

                "created": artifact.created.isoformat(),

                "modified": artifact.modified.isoformat(),

                "accessed": artifact.accessed.isoformat(),

                "description": artifact.description

            })

        with open(output_file, "w", encoding="utf-8") as f:

            json.dump(output, f, indent=4, ensure_ascii=False)

    def summary(self) -> dict[str, int]:
        counts = Counter(
            artifact.artifact_type.value
            for artifact in self.artifacts
        )

        counts = dict(sorted(counts.items()))

        counts["TOTAL"] = len(self.artifacts)

        return counts

    def print_summary(self):

        summary = self.summary()

        print("\n========== INVENTORY SUMMARY ==========\n")

        for artifact_type, count in summary.items():
            print(f"{artifact_type:<20}: {count}")

        print()

    def export_summary_json(self, output_file):

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(self.summary(), f, indent=4)        