import pytest
from rbac_rag.acl.policy import Policy
from rbac_rag.acl.policy_store import PolicyStore, PolicyError

pytestmark = pytest.mark.db


def sample_policy(version: int = 1, name: str = "v1") -> Policy:
    return Policy.from_dict({
        "version": version,
        "name": name,
        "description": f"Description for {name}",
        "classifications": {"public": 0, "confidential": 10},
        "roles": {
            "user": {"clearance": 0, "inherits": []},
            "admin": {"clearance": 10, "inherits": ["user"]},
        },
        "groups": {
            "admins": ["admin"],
        },
        "deny_rules": [],
    })


def test_policy_store_publish_idempotent_and_activate(db_conn):
    store = PolicyStore(db_conn)
    p = sample_policy(1, "v1")

    created = store.publish(p, activate=True)
    assert created is True
    assert store.active_version() == 1

    # Re-publishing identical version is a no-op returning False
    created_again = store.publish(p, activate=True)
    assert created_again is False


def test_policy_store_same_version_different_content_raises(db_conn):
    store = PolicyStore(db_conn)
    p1 = sample_policy(1, "v1")
    store.publish(p1)

    p2 = Policy.from_dict({
        "version": 1,  # same version
        "name": "v1_modified",
        "classifications": {"public": 0, "secret": 50},  # different content
        "roles": {},
    })

    with pytest.raises(PolicyError, match="already exists with different content"):
        store.publish(p2)


def test_policy_store_only_one_active_version(db_conn):
    store = PolicyStore(db_conn)
    p1 = sample_policy(1, "v1")
    p2 = sample_policy(2, "v2")

    store.publish(p1, activate=True)
    assert store.active_version() == 1

    store.publish(p2, activate=True)
    assert store.active_version() == 2

    # Check database directly to ensure only 1 is active
    active_count = db_conn.execute("SELECT count(*) FROM policy_versions WHERE is_active").fetchone()[0]
    assert active_count == 1

    # Switch back to v1
    store.activate(1)
    assert store.active_version() == 1


def test_policy_store_get_roundtrip_equal_policy(db_conn):
    store = PolicyStore(db_conn)
    p1 = sample_policy(1, "v1")
    store.publish(p1)

    loaded_p1 = store.get(1)
    assert loaded_p1 == p1
    assert loaded_p1.checksum() == p1.checksum()


def test_policy_store_resolve_version(db_conn):
    store = PolicyStore(db_conn)
    p1 = sample_policy(1, "v1")
    store.publish(p1, activate=True)

    # resolve_version(None) returns active version
    assert store.resolve_version(None) == 1
    assert store.resolve_version(1) == 1

    with pytest.raises(PolicyError, match="does not exist"):
        store.resolve_version(99)
