import pytest
from rbac_rag.acl.policy import Policy, RoleDef, DenyRule, Decision, Subject, diff_policies
from rbac_rag.types import Acl, Principal, PrincipalType


def make_sample_policy_dict():
    return {
        "version": 1,
        "name": "sample_policy",
        "description": "Sample policy description",
        "classifications": {
            "public": 0,
            "internal": 10,
            "confidential": 20,
            "restricted": 30,
        },
        "roles": {
            "employee": {"clearance": 10, "inherits": []},
            "engineer": {"clearance": 20, "inherits": ["employee"]},
            "lead_engineer": {"clearance": 20, "inherits": ["engineer"]},
            "exec": {"clearance": 30, "inherits": []},
        },
        "groups": {
            "eng_group": ["engineer"],
            "exec_group": ["exec"],
        },
        "deny_rules": [
            {"principal": "role:employee", "classification": "restricted"},
        ],
    }


def test_policy_validate_errors():
    # Non-positive version
    d = make_sample_policy_dict()
    d["version"] = 0
    with pytest.raises(ValueError, match="policy version must be positive"):
        Policy.from_dict(d)

    # Undefined role in inherits
    d = make_sample_policy_dict()
    d["roles"]["bad_role"] = {"clearance": 0, "inherits": ["ghost"]}
    with pytest.raises(ValueError, match="inherits undefined role 'ghost'"):
        Policy.from_dict(d)

    # Undefined role in groups
    d = make_sample_policy_dict()
    d["groups"]["bad_group"] = ["ghost"]
    with pytest.raises(ValueError, match="maps to undefined role 'ghost'"):
        Policy.from_dict(d)

    # Undefined classification in deny rules
    d = make_sample_policy_dict()
    d["deny_rules"].append({"principal": "user:alice", "classification": "top_secret"})
    with pytest.raises(ValueError, match="uses undefined classification 'top_secret'"):
        Policy.from_dict(d)


def test_policy_inheritance_closure_including_cycles():
    # Construct policy with role inheritance cycle (a -> b -> c -> a) manually to test closure termination
    roles = {
        "a": RoleDef("a", clearance=5, inherits=("b",)),
        "b": RoleDef("b", clearance=10, inherits=("c",)),
        "c": RoleDef("c", clearance=15, inherits=("a",)),
        "standalone": RoleDef("standalone", clearance=10, inherits=()),
    }
    policy = Policy(
        version=1,
        name="cyclic",
        classifications={"public": 0},
        roles=roles,
    )

    eff = policy.effective_roles(roles={"a"}, groups=set())
    assert eff == {"a", "b", "c"}
    assert policy.clearance(eff) == 15


def test_policy_group_to_role_mapping_undefined_roles_dropped():
    d = make_sample_policy_dict()
    policy = Policy.from_dict(d)

    # If caller passes an undefined role in `roles` parameter to effective_roles:
    eff = policy.effective_roles(roles={"engineer", "undefined_role"}, groups={"eng_group"})
    assert "undefined_role" not in eff
    assert eff == {"engineer", "employee"}


def test_policy_clearance_calculation():
    d = make_sample_policy_dict()
    policy = Policy.from_dict(d)

    eff1 = policy.effective_roles(roles=set(), groups=set())
    assert policy.clearance(eff1) == 0

    eff2 = policy.effective_roles(roles={"engineer"}, groups=set())
    assert policy.clearance(eff2) == 20  # engineer (20) & employee (10) -> max is 20


def test_policy_decide_unknown_user():
    d = make_sample_policy_dict()
    policy = Policy.from_dict(d)

    decision = policy.decide(
        subject=None,
        classification="public",
        acl=Acl.from_specs(allow=["role:engineer"]),
    )
    assert not decision.allowed
    assert "unknown user" in decision.reason


def test_policy_decide_unknown_classification():
    d = make_sample_policy_dict()
    policy = Policy.from_dict(d)

    subj = policy.subject(user_id="alice", groups=set(), roles={"engineer"})
    decision = policy.decide(
        subject=subj,
        classification="unknown_class",
        acl=Acl.from_specs(allow=["role:engineer"]),
    )
    assert not decision.allowed
    assert "not defined in policy" in decision.reason


def test_policy_decide_clearance_too_low():
    d = make_sample_policy_dict()
    policy = Policy.from_dict(d)

    subj = policy.subject(user_id="bob", groups=set(), roles={"employee"})  # clearance 10
    decision = policy.decide(
        subject=subj,
        classification="confidential",  # requires 20
        acl=Acl.from_specs(allow=["role:employee"]),
    )
    assert not decision.allowed
    assert "clearance 10 < 20 required" in decision.reason


def test_policy_decide_missing_allow_denied():
    d = make_sample_policy_dict()
    policy = Policy.from_dict(d)

    subj = policy.subject(user_id="alice", groups=set(), roles={"engineer"})
    decision = policy.decide(
        subject=subj,
        classification="public",
        acl=Acl.from_specs(allow=["role:exec"]),  # alice doesn't have role:exec
    )
    assert not decision.allowed
    assert "no matching allow" in decision.reason


def test_policy_decide_explicit_deny_beats_allow():
    d = make_sample_policy_dict()
    policy = Policy.from_dict(d)

    subj = policy.subject(user_id="alice", groups=set(), roles={"engineer"})
    decision = policy.decide(
        subject=subj,
        classification="public",
        acl=Acl.from_specs(allow=["role:engineer"], deny=["user:alice"]),
    )
    assert not decision.allowed
    assert "explicit deny" in decision.reason


def test_policy_decide_policy_deny_rule():
    d = make_sample_policy_dict()
    policy = Policy.from_dict(d)

    # exec clearance is 30, employee has deny rule for restricted classification
    subj = policy.subject(user_id="charlie", groups=set(), roles={"exec", "employee"})
    decision = policy.decide(
        subject=subj,
        classification="restricted",  # requires 30, charlie has clearance 30, but employee role is denied restricted
        acl=Acl.from_specs(allow=["role:exec"]),
    )
    assert not decision.allowed
    assert "policy deny rule" in decision.reason


def test_policy_checksum_ignores_version_name_description():
    d1 = make_sample_policy_dict()
    p1 = Policy.from_dict(d1)

    d2 = make_sample_policy_dict()
    d2["version"] = 99
    d2["name"] = "different_name"
    d2["description"] = "different_description"
    p2 = Policy.from_dict(d2)

    assert p1.checksum() == p2.checksum()


def test_diff_policies_output():
    d1 = make_sample_policy_dict()
    p1 = Policy.from_dict(d1)

    d2 = make_sample_policy_dict()
    d2["version"] = 2
    d2["classifications"]["top_secret"] = 40
    d2["roles"]["auditor"] = {"clearance": 15, "inherits": []}
    d2["groups"]["eng_group"] = ["engineer", "auditor"]
    d2["deny_rules"] = []
    p2 = Policy.from_dict(d2)

    diff = diff_policies(p1, p2)

    assert diff["from"] == 1
    assert diff["to"] == 2
    assert "top_secret" in diff["classifications"]["added"]
    assert "auditor" in diff["roles"]["added"]
    assert "eng_group" in diff["groups"]["changed"]
    assert len(diff["deny_rules"]["removed"]) == 1
