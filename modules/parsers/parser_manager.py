from modules.discovery.artifact import Artifact
from modules.discovery.artifact_type import ArtifactType

from modules.parsers.evtx.evtx_parser import EVTXParser
from modules.parsers.prefetch.prefetch_parser import PrefetchParser
from modules.parsers.registry.registry_parser import RegistryParser
from modules.parsers.lnk.lnk_parser import LNKParser
from modules.parsers.jumplist.jumplist_parser import JumpListParser
from modules.parsers.browser.browser_parser import BrowserParser
from modules.parsers.sru.sru_parser import SRUParser
from modules.parsers.mft.mft_parser import MFTParser
from modules.parsers.amcache.amcache_parser import AmcacheParser
from modules.parsers.usn.usn_parser import USNParser
from modules.parsers.scheduled_task.scheduled_task_parser import ScheduledTaskParser
class ParserManager:
    """
    Sélectionne automatiquement le bon parser
    en fonction du type d'artefact.
    """

    def __init__(self):

        self.parsers = {

            ArtifactType.EVTX: EVTXParser(),



            # ArtifactType.PREFETCH: PrefetchParser(),
            ArtifactType.PREFETCH: PrefetchParser(),

            # ArtifactType.REGISTRY_SYSTEM: RegistryParser(),
            # ArtifactType.REGISTRY_SOFTWARE: RegistryParser(),
            # ArtifactType.REGISTRY_SECURITY: RegistryParser(),
            # ArtifactType.REGISTRY_SAM: RegistryParser(),
            # ArtifactType.REGISTRY_NTUSER: RegistryParser(),
            # ArtifactType.USRCLASS: RegistryParser(),
            ArtifactType.REGISTRY_SYSTEM: RegistryParser(),
            ArtifactType.REGISTRY_SOFTWARE: RegistryParser(),
            ArtifactType.REGISTRY_SECURITY: RegistryParser(),
            ArtifactType.REGISTRY_SAM: RegistryParser(),
            ArtifactType.REGISTRY_DEFAULT: RegistryParser(),
            ArtifactType.REGISTRY_NTUSER: RegistryParser(),
            ArtifactType.USRCLASS: RegistryParser(),

            # ArtifactType.LNK: LNKParser(),
            ArtifactType.LNK: LNKParser(),

            # ArtifactType.JUMPLIST: JumpListParser(),
            ArtifactType.JUMPLIST: JumpListParser(),

            # ArtifactType.MFT: MFTParser(),
            ArtifactType.MFT:MFTParser(),

            ArtifactType.USN: USNParser(),

            # ArtifactType.SRU: SRUParser(),
            ArtifactType.SRU: SRUParser(),

            # Browser
            ArtifactType.BROWSER: BrowserParser(),

            #Amcache
            ArtifactType.AMCACHE: AmcacheParser(),
            #tasks
            ArtifactType.SCHEDULED_TASK: ScheduledTaskParser(),

        }

    def get_parser(self, artifact_type: ArtifactType):

        return self.parsers.get(artifact_type)

    def parse(self, artifact: Artifact):

        parser = self.get_parser(artifact.artifact_type)
        try:
            if parser is None:

                return []

            return parser.parse(artifact.path)
        except Exception as e:
            print(f"[PARSER MANAGER ERROR] {artifact.path}: {e}")
            return []
