from __future__ import annotations

from collections import Counter

from modules.ioc.ioc_models import IOC


def compute_statistics(iocs: list[IOC]) -> dict[str, int]:
    """Count IOCs by type, keyed by IOCType.value (e.g. "ipv4",
    "hash_sha1") -- the shape ioc_summary.json's "ioc_statistics"
    field uses."""
    counter: Counter[str] = Counter(ioc.ioc_type.value for ioc in iocs)
    return dict(sorted(counter.items()))