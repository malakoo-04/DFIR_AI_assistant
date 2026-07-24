from enum import IntEnum


class IdentityStrength(IntEnum):
    """
    Confidence level of an identity key — or, for a freshly created Entity
    with no key assigned yet, the current quality of its identity.

    VERY_WEAK is distinct from WEAK on purpose: WEAK means "backed by a
    real but weak identity key" (e.g. a bare filename via the resolver's
    fallback path); VERY_WEAK means "no meaningful identity evidence has
    been attached yet" — two different states, not the same thing.

    Higher values are preferred by the EntityResolver.
    """

    VERY_WEAK = 0
    WEAK = 1
    MEDIUM = 2
    STRONG = 3