import copy
import json
from pathlib import Path

import pytest

from allowlist import (
    HARD_DENIED_POLICIES,
    check_mapping,
    load_allowlist,
    load_checked_mapping,
    parse_allowlist,
)
from mapping import MappingError, parse_mapping

ROOT = Path(__file__).resolve().parents[1]
RO = "arn:aws:iam::aws:policy/ReadOnlyAccess"
POWER = "arn:aws:iam::aws:policy/PowerUserAccess"
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"

ALLOW = {
    "version": 1,
    "policies": {
        RO: {"tier": "standard", "max_session_duration": "PT8H", "reason": "View only access"},
        POWER: {"tier": "privileged", "max_session_duration": "PT4H", "reason": "Engineers build workloads"},
    },
}


def mapping_with(policy, duration="PT4H", justification=""):
    ps = {"name": "Henz-X", "session_duration": duration, "managed_policies": [policy]}
    if justification:
        ps["justification"] = justification
    return parse_mapping({
        "version": 1,
        "managed_tag": {"key": "managed-by", "value": "henz-iga"},
        "mappings": [{"group": "AWS-IT-X", "permission_set": ps}],
    })


def allow(**changes):
    doc = copy.deepcopy(ALLOW)
    doc.update(changes)
    return doc


def allow_problems(doc):
    with pytest.raises(MappingError) as exc:
        parse_allowlist(doc)
    return exc.value.problems


# ------------------------------------------------------------------ the real files

def test_real_files_are_valid_together():
    mapping = load_checked_mapping(ROOT / "mapping" / "mapping.json", ROOT / "mapping" / "policy-allowlist.json")
    assert len(mapping.mappings) == 4


def test_real_allowlist_has_a_readme_that_explains_the_file():
    doc = json.loads((ROOT / "mapping" / "policy-allowlist.json").read_text())
    assert doc["_readme"] and "ALLOW" in " ".join(doc["_readme"]).upper()
    assert load_allowlist(ROOT / "mapping" / "policy-allowlist.json").policies


# ------------------------------------------------------------- allow-list file itself

def test_good_allowlist_parses():
    allowlist = parse_allowlist(ALLOW)
    assert allowlist.policies[POWER].tier == "privileged"
    assert allowlist.policies[POWER].max_session_minutes == 240


def test_readme_key_is_accepted_and_ignored():
    assert parse_allowlist(allow(_readme=["notes", "more notes"])).policies


def test_unknown_top_level_key_is_rejected_so_typos_are_caught():
    assert any("unknown top-level key" in p for p in allow_problems(allow(polices={})))


def test_hard_denied_policy_cannot_be_allowed_even_when_listed():
    for arn in HARD_DENIED_POLICIES:
        doc = allow()
        doc["policies"][arn] = {"tier": "standard", "max_session_duration": "PT1H", "reason": "Trying to sneak in"}
        assert any("never allowed" in p for p in allow_problems(doc))


def test_privileged_policy_cannot_allow_long_sessions():
    doc = allow()
    doc["policies"][POWER]["max_session_duration"] = "PT8H"
    assert any("PT4H" in p for p in allow_problems(doc))


@pytest.mark.parametrize("bad", [
    {"tier": "VIP", "max_session_duration": "PT4H", "reason": "long enough reason"},
    {"tier": "standard", "max_session_duration": "forever", "reason": "long enough reason"},
    {"tier": "standard", "max_session_duration": "PT4H", "reason": "short"},
    {"tier": "standard", "max_session_duration": "PT4H", "reason": "long enough reason", "extra": 1},
])
def test_bad_entries_are_rejected(bad):
    doc = allow()
    doc["policies"][RO] = bad
    assert allow_problems(doc)


def test_non_aws_managed_key_is_rejected():
    doc = allow()
    doc["policies"]["arn:aws:iam::123456789012:policy/Custom"] = ALLOW["policies"][RO]
    assert any("AWS managed policy ARN" in p for p in allow_problems(doc))


def test_load_rejects_missing_and_invalid_files(tmp_path):
    with pytest.raises(MappingError):
        load_allowlist(tmp_path / "nope.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{oops")
    with pytest.raises(MappingError):
        load_allowlist(bad)


# --------------------------------------------------------- mapping against the allow-list

def test_standard_policy_passes_without_justification():
    assert check_mapping(mapping_with(RO, "PT8H"), parse_allowlist(ALLOW)) == []


def test_policy_not_on_the_list_is_rejected():
    problems = check_mapping(mapping_with(ADMIN, "PT1H", "x" * 30), parse_allowlist(ALLOW))
    assert any("not in the policy allow-list" in p for p in problems)


def test_hard_denied_policy_is_rejected_in_a_mapping():
    arn = "arn:aws:iam::aws:policy/IAMFullAccess"
    problems = check_mapping(mapping_with(arn, "PT1H", "x" * 30), parse_allowlist(ALLOW))
    assert any("never allowed" in p for p in problems)


def test_privileged_policy_needs_a_justification():
    problems = check_mapping(mapping_with(POWER, "PT4H"), parse_allowlist(ALLOW))
    assert any("justification" in p for p in problems)


def test_privileged_policy_with_justification_passes():
    assert check_mapping(mapping_with(POWER, "PT4H", "Engineers run the lab workloads"), parse_allowlist(ALLOW)) == []


def test_session_longer_than_the_limit_is_rejected():
    problems = check_mapping(mapping_with(POWER, "PT8H", "Engineers run the lab workloads"), parse_allowlist(ALLOW))
    assert any("longer than" in p for p in problems)


def test_load_checked_mapping_refuses_a_bad_mapping(tmp_path):
    m = tmp_path / "mapping.json"
    a = tmp_path / "allow.json"
    a.write_text(json.dumps(ALLOW))
    m.write_text(json.dumps({
        "version": 1, "managed_tag": {"key": "managed-by", "value": "henz-iga"},
        "mappings": [{"group": "AWS-IT-X", "permission_set": {
            "name": "Henz-X", "session_duration": "PT1H", "managed_policies": [ADMIN]}}],
    }))
    with pytest.raises(MappingError) as exc:
        load_checked_mapping(m, a)
    assert any("allow-list" in p for p in exc.value.problems)
