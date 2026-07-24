from modules.models.event_category import EventCategory
from modules.models.event_type import EventType
from modules.normalizer.base_normalizer import BaseNormalizer
from modules.normalizer.event import create_event


class AmcacheNormalizer(BaseNormalizer):
    """
    Normalise les entrées Amcache
    en événements DFIR homogènes.
    """

    IMPORTANT_CATEGORIES = {
        "InventoryApplication",
        "InventoryApplicationFile",
        "InventoryApplicationShortcut",
        "InventoryDriverBinary",
        "InventoryDriverPackage",
    }

    CONFIDENCE_MAP = {
        "InventoryApplication": 0.80,
        "InventoryApplicationFile": 0.70,
        "InventoryApplicationShortcut": 0.60,
        "InventoryDriverBinary": 0.85,
        "InventoryDriverPackage": 0.85,
    }

    def normalize(self, record: dict) -> list[dict]:

        if record.get("artifact_type") != "amcache":
            return []

        category = record.get("category")

        # Ignore les catégories peu utiles pour l'analyse DFIR
        if category not in self.IMPORTANT_CATEGORIES:
            return []

        timestamp = (
            record.get("last_written")
            or record.get("InstallDate")
            or record.get("DriverLastWriteTime")
        )

        # Nom de l'objet
        name = (
            record.get("Name")
            or record.get("ProgramName")
            or record.get("DriverName")
            or record.get("FileName")
            or record.get("entry_name")
        )

        # Chemin
        path = (
            record.get("LowerCaseLongPath")
            or record.get("Path")
            or record.get("FilePath")
            or record.get("Directory")
            or record.get("entry_path")
        )

        # Hash
        sha1 = (
            record.get("SHA1")
            or record.get("Sha1")
            or record.get("FileId")
            or record.get("ProgramId")
            or record.get("DriverId")
        )

        publisher = (
            record.get("Publisher")
            or record.get("CompanyName")
            or record.get("DriverCompany")
        )

        version = (
            record.get("Version")
            or record.get("ProductVersion")
            or record.get("DriverVersion")
        )

        event = create_event(
            artifact_type="amcache",
            event_type=EventType.APPLICATION_INVENTORY,
            category=EventCategory.SYSTEM,
            timestamp=timestamp,
            object_name=name,
            object_path=path,
            description=f"Amcache {category} entry: {name or path or 'unknown'}",
            # Amcache proves presence/registration in the software inventory,
            # not necessarily execution — same caution as UserAssist, hence
            # not defaulting to a near-certain confidence.
            confidence=self.CONFIDENCE_MAP.get(category,0.75),
            evidence={
                "amcache_category": category,
            },
            source_file=record.get("source_path"),
            raw_data=record,
        )
        event.update({
            "sha1": sha1,
            "publisher": publisher,
            "version": version,
            "amcache_category": category,
        })

        return [event]