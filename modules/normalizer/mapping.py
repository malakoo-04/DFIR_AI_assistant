from modules.normalizer.normalizers.prefetch import PrefetchNormalizer
from modules.normalizer.normalizers.browser import BrowserNormalizer
from modules.normalizer.normalizers.evtx import EVTXNormalizer
from modules.normalizer.normalizers.lnk import LNKNormalizer
from modules.normalizer.normalizers.jumplist import JumpListNormalizer
from modules.normalizer.normalizers.amcache import AmcacheNormalizer
from modules.normalizer.normalizers.registry import RegistryNormalizer
from modules.normalizer.normalizers.usn import USNNormalizer
from modules.normalizer.normalizers.sru import SRUNormalizer
from modules.normalizer.normalizers.defender import DefenderNormalizer
from modules.normalizer.normalizers.scheduled_task import ScheduledTaskNormalizer
from modules.normalizer.normalizers.mft import MFTNormalizer
NORMALIZER_MAPPING = {

    "prefetch": PrefetchNormalizer(),

    "browser": BrowserNormalizer(),

    "registry": RegistryNormalizer(),

    "lnk": LNKNormalizer(),

    "jumplist": JumpListNormalizer(),

    "evtx": EVTXNormalizer(),

    "mft": MFTNormalizer(),

    "usn": USNNormalizer(),

    "sru": SRUNormalizer(),

    "amcache": AmcacheNormalizer(),

    "defender":DefenderNormalizer(),

    "scheduled_task":ScheduledTaskNormalizer(),


}
