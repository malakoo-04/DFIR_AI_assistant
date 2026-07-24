from dataclasses import dataclass
from pathlib import Path
from .artifact_type import ArtifactType

@dataclass(slots=True)
class Signature:
    """
    Décrit une règle permettant d'identifier
    un artefact dans une collecte KAPE ou FastIR.
    """

    name: str
    artifact_type: ArtifactType
    pattern: str | None = None
    parser: str | None = None
    description: str | None = ""
    priority: int = 100
    enabled: bool = True
    
    # Nouveaux critères multi-attributs pour une détection robuste
    filename: str | None = None
    extension: str | None = None
    parent: str | None = None

    def matches(self, path: Path) -> bool:
        """
        Vérifie si le chemin correspond aux critères définis.
        L'évaluation est entièrement INSENSIBLE À LA CASSE.
        Tous les critères spécifiés (non None) doivent correspondre (ET logique).
        """
        if not (self.filename or self.extension or self.parent or self.pattern):
            return False

        # 1. Vérification de l'extension (ex: '.pf', '.lnk')
        if self.extension:
            if path.suffix.lower() != self.extension.lower():
                return False

        # 2. Vérification du nom de fichier exact (ex: 'SYSTEM', 'Amcache.hve')
        if self.filename:
            if path.name.lower() != self.filename.lower():
                return False

        # 3. Vérification du dossier parent (ex: 'prefetch', 'config')
        if self.parent:
            parent_names = [p.name.lower() for p in path.parents]
            if self.parent.lower() not in parent_names:
                return False

        # 4. Fallback sur le pattern glob classique (si spécifié)
        if self.pattern:
            # On force le chemin en minuscules pour s'assurer que le match soit cross-platform
            if not Path(str(path).lower()).match(self.pattern.lower()):
                return False

        return True