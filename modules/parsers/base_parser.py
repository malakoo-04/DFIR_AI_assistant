from abc import ABC, abstractmethod
from pathlib import Path


class BaseParser(ABC):
    """
    Classe de base pour tous les parseurs du framework DFIR-AI.
    """

    @abstractmethod
    def parse(self, artifact_path: Path) -> list[dict]:
        """
        Parse un artefact et retourne une liste de dictionnaires.
        """
        pass

    def handle_error(self, artifact_path: Path, exception: Exception) -> list[dict]:
        """
        Gère les erreurs de parsing sans interrompre le pipeline.
        """
        print(f"\n[{self.__class__.__name__}] Failed to parse:")
        print(f"  File : {artifact_path}")
        print(f"  Error: {exception}\n")

        return []