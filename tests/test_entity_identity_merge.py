from modules.correlation.identity import EntityResolver
from modules.correlation.models import Entity
from modules.models.entity_type import EntityType
from modules.models.identity_key import IdentityKey
from modules.models.identity_strength import IdentityStrength


def _entity(name="original.exe", path="C:\\old\\original.exe", rank=IdentityStrength.MEDIUM):
    return Entity(
        entity_id="entity",
        entity_type=EntityType.FILE,
        name=name,
        canonical_path=path,
        metadata={"_identity_rank": int(rank)},
    )


def _key(strength):
    return IdentityKey("path", "value", EntityType.FILE, strength)


def test_merge_into_keeps_name_independent_and_only_upgrades_stronger_path():
    resolver = EntityResolver()
    entity = _entity(rank=IdentityStrength.MEDIUM)
    resolver._entities[entity.entity_id] = entity
    resolver._parent[entity.entity_id] = entity.entity_id

    resolver._merge_into(
        entity.entity_id,
        [_key(IdentityStrength.STRONG)],
        {"object_name": "new-name.exe", "object_path": "C:\\trusted\\new.exe"},
    )

    assert entity.name == "original.exe"
    assert "new-name.exe" in entity.aliases
    assert "C:\\old\\original.exe" in entity.aliases
    assert entity.canonical_path == "C:\\trusted\\new.exe"
    assert entity.metadata["_identity_rank"] == int(IdentityStrength.STRONG)


def test_merge_into_backfills_path_without_changing_rank():
    resolver = EntityResolver()
    entity = _entity(path=None, rank=IdentityStrength.STRONG)
    resolver._entities[entity.entity_id] = entity
    resolver._parent[entity.entity_id] = entity.entity_id

    resolver._merge_into(
        entity.entity_id,
        [_key(IdentityStrength.WEAK)],
        {"object_name": "other.exe", "object_path": "C:\\fallback\\other.exe"},
    )

    assert entity.canonical_path == "C:\\fallback\\other.exe"
    assert entity.metadata["_identity_rank"] == int(IdentityStrength.STRONG)
    assert "other.exe" in entity.aliases


def test_merge_entity_data_preserves_name_and_promotes_only_stronger_path():
    resolver = EntityResolver()
    survivor = _entity(name="survivor.exe", path="C:\\weak\\survivor.exe", rank=IdentityStrength.MEDIUM)
    absorbed = Entity(
        entity_id="absorbed",
        entity_type=EntityType.FILE,
        name="absorbed.exe",
        canonical_path="C:\\strong\\absorbed.exe",
        metadata={"_identity_rank": int(IdentityStrength.STRONG)},
    )

    resolver._merge_entity_data(survivor, absorbed)

    assert survivor.name == "survivor.exe"
    assert "absorbed.exe" in survivor.aliases
    assert "C:\\weak\\survivor.exe" in survivor.aliases
    assert survivor.canonical_path == "C:\\strong\\absorbed.exe"
    assert survivor.metadata["_identity_rank"] == int(IdentityStrength.STRONG)
