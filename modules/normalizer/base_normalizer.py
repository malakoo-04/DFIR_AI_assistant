from abc import ABC, abstractmethod


class BaseNormalizer(ABC):
    """
    Classe de base de tous les normalizers.

    Chaque normalizer reçoit un dictionnaire produit
    par un parser et retourne un dictionnaire normalisé.
    """

    @abstractmethod
    def normalize(self,record:dict) -> list[dict]:
        """
         Transforme un enregistrement parser en un ou plusieurs
        événements normalisés.
        """
        pass