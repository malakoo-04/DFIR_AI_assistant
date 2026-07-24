from dataclasses import dataclass #domain model
from datetime import datetime 
from pathlib import Path

from .artifact_type import ArtifactType


@dataclass(slots=True)
class Artifact:
    """
    Représente un artefact découvert
    dans une collecte KAPE.
    """

    name: str

    path: Path

    artifact_type: ArtifactType

    #parser: str   #parser=ex:EVTXParser 

    size: int   #statistiques ou detection de corruption

    created: datetime | None  

    modified: datetime | None

    accessed: datetime | None  #timeline/correlation/anomalie

    description: str

    sha256: str | None = None