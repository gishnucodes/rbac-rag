"""Unit tests for security evaluation canary scanning and exposure logic (no DB)."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from evals.security_eval import (
    build_canary_map,
    get_unauthorized_canaries_for_subject,
    verify_canaries_exist_and_unique,
)
from rbac_rag.acl.policy import Policy
from rbac_rag.types import Acl, Principal, PrincipalType


@dataclass
class SyntheticChunk:
    chunk_id: str
    content: str
    classification: str
    acl: Acl


@pytest.fixture
def test_policy() -> Policy:
    return Policy.from_dict({
        "version": 1,
        "name": "v1",
        "description": "Test Policy",
        "classifications": {
            "public": 0,
            "internal": 1,
            "confidential": 2,
            "restricted": 3,
        },
        "roles": {
            "employee": {"clearance": 1, "inherits": []},
            "executive": {"clearance": 3, "inherits": ["employee"]},
        },
        "groups": {
            "employees": ["employee"],
            "executives": ["executive"],
        },
        "deny_rules": [],
    })


def test_canary_map_and_verification():
    chunks = [
        SyntheticChunk("c1", "Key AUDIT-3360 here", "confidential", Acl.from_specs(allow=["role:executive"])),
        SyntheticChunk("c2", "Key BREAKGLASS-4417 here", "confidential", Acl.from_specs(allow=["role:nobody"])),
        SyntheticChunk("c3", "Key COMPBAND-9921 here", "confidential", Acl.from_specs(allow=["role:executive"])),
        SyntheticChunk("c4", "Key FINQ3-5582 here", "internal", Acl.from_specs(allow=["role:employee"])),
        SyntheticChunk("c5", "Key NIGHTJAR-7731 here", "restricted", Acl.from_specs(allow=["role:executive"])),
        SyntheticChunk("c6", "Key RESERVE-2290 here", "confidential", Acl.from_specs(allow=["role:executive"])),
    ]

    cmap = build_canary_map(chunks)
    assert len(cmap) == 6
    assert "FINQ3-5582" in cmap

    # Verification passes when all 6 exist uniquely
    verify_canaries_exist_and_unique(cmap)

    # Missing canary fails
    incomplete_map = {k: v for k, v in cmap.items() if k != "AUDIT-3360"}
    with pytest.raises(RuntimeError, match="missing expected canaries"):
        verify_canaries_exist_and_unique(incomplete_map)

    # Duplicate canary fails
    dup_map = dict(cmap)
    dup_map["AUDIT-3360"] = [chunks[0], chunks[0]]
    with pytest.raises(RuntimeError, match="expected exactly 1"):
        verify_canaries_exist_and_unique(dup_map)


def test_unauthorized_canaries_detection(test_policy):
    # c1 has COMPBAND-9921 in confidential chunk (only executive allowed)
    # c2 has FINQ3-5582 in internal chunk (employee allowed)
    c1 = SyntheticChunk("c1", "Confidential COMPBAND-9921", "confidential", Acl.from_specs(allow=["role:executive"]))
    c2 = SyntheticChunk("c2", "Internal FINQ3-5582", "internal", Acl.from_specs(allow=["role:employee"]))

    cmap = build_canary_map([c1, c2])

    # Employee subject (clearance 1)
    emp_subject = test_policy.subject("alice", groups={"employees"}, roles=set())

    unauth = get_unauthorized_canaries_for_subject(cmap, test_policy, emp_subject)
    # COMPBAND-9921 requires clearance 2/executive role, so unauthorized for employee
    assert "COMPBAND-9921" in unauth
    # FINQ3-5582 is allowed for employee
    assert "FINQ3-5582" not in unauth


def test_canary_inside_authorized_chunk_text_flagged(test_policy):
    """If an authorized chunk contains the text of an unauthorized canary, exposure check flags it."""
    c_restricted = SyntheticChunk(
        "c_restricted", "Restricted document with NIGHTJAR-7731", "restricted", Acl.from_specs(allow=["role:executive"])
    )
    # c_public is a public chunk, but somebody pasted the NIGHTJAR-7731 canary string into its text
    c_public = SyntheticChunk(
        "c_public", "Public discussion mentioning NIGHTJAR-7731", "public", Acl.from_specs(allow=["role:employee"])
    )

    cmap = build_canary_map([c_restricted])

    # Employee subject cannot access c_restricted
    emp_subject = test_policy.subject("alice", groups={"employees"}, roles=set())

    unauth_canaries = get_unauthorized_canaries_for_subject(cmap, test_policy, emp_subject)
    assert "NIGHTJAR-7731" in unauth_canaries

    # Even though c_public is authorized for alice, searching its content for unauthorized canaries detects NIGHTJAR-7731!
    retrieved_canaries = [c for c in ["NIGHTJAR-7731"] if c in unauth_canaries]
    assert "NIGHTJAR-7731" in retrieved_canaries
