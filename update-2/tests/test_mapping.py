import copy
import json
from pathlib import Path

import pytest

from mapping import MappingError, load_mapping, parse_mapping

REAL_FILE = Path(__file__).resolve().parents[1] / "mapping" / "mapping.json"

GOOD = {
    "version": 1,
    "managed_tag": {"key": "managed-by", "value": "henz-iga"},
    "mappings": [
        {
            "group": "AWS-IT-ReadOnly",
            "permission_set": {
                "name": "Henz-IT-ReadOnly",
                "description": "Read only",
                "session_duration": "PT8H",
                "managed_policies": ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
            },
        }
    ],
}


def variant(mutate):
    doc = copy.deepcopy(GOOD)
    mutate(doc)
    return doc


def problems_for(doc):
    with pytest.raises(MappingError) as exc:
        parse_mapping(doc)
    return exc.value.problems


def test_real_mapping_file_is_valid():
    mapping = load_mapping(REAL_FILE)
    assert [m.group for m in mapping.mappings] == ["AWS-IT-ReadOnly", "AWS-IT-PowerUsers", "AWS-IT-Security"]
    assert mapping.mappings[0].permission_set_name == "Henz-IT-ReadOnly"
    assert mapping.watch_prefix == "AWS-IT-"


def test_good_document_parses():
    mapping = parse_mapping(GOOD)
    assert mapping.managed_tag_key == "managed-by"
    assert mapping.mappings[0].managed_policies == ("arn:aws:iam::aws:policy/ReadOnlyAccess",)


def test_rejects_wrong_version():
    assert any("version" in p for p in problems_for(variant(lambda d: d.update(version=2))))


def test_rejects_missing_tag():
    assert any("managed_tag" in p for p in problems_for(variant(lambda d: d.pop("managed_tag"))))


def test_rejects_empty_mappings():
    assert any("mappings" in p for p in problems_for(variant(lambda d: d.update(mappings=[]))))


def test_rejects_duplicate_group():
    def mutate(d):
        second = copy.deepcopy(d["mappings"][0])
        second["group"] = "aws-it-readonly"  # same group, different case
        second["permission_set"]["name"] = "Other-Name"
        d["mappings"].append(second)

    assert any("more than once" in p for p in problems_for(variant(mutate)))


def test_rejects_shared_permission_set_one_to_one_violation():
    def mutate(d):
        second = copy.deepcopy(d["mappings"][0])
        second["group"] = "AWS-IT-Support"  # different group, same permission set
        d["mappings"].append(second)

    assert any("1:1" in p for p in problems_for(variant(mutate)))


@pytest.mark.parametrize("name", ["", "x" * 33, "bad name", "bad/name"])
def test_rejects_bad_permission_set_name(name):
    def mutate(d):
        d["mappings"][0]["permission_set"]["name"] = name

    assert any("name" in p for p in problems_for(variant(mutate)))


@pytest.mark.parametrize("arn", [
    "arn:aws:iam::123456789012:policy/CustomerManaged",  # customer managed: not allowed in v1
    "ReadOnlyAccess",
    "arn:aws:iam::aws:policy/",
])
def test_rejects_non_aws_managed_policy(arn):
    def mutate(d):
        d["mappings"][0]["permission_set"]["managed_policies"] = [arn]

    assert any("AWS managed policy" in p for p in problems_for(variant(mutate)))


def test_rejects_empty_policy_list():
    def mutate(d):
        d["mappings"][0]["permission_set"]["managed_policies"] = []

    assert any("managed_policies" in p for p in problems_for(variant(mutate)))


@pytest.mark.parametrize("duration", ["PT", "PT30M", "PT13H", "8H", "P1D"])
def test_rejects_bad_session_duration(duration):
    def mutate(d):
        d["mappings"][0]["permission_set"]["session_duration"] = duration

    assert any("session_duration" in p for p in problems_for(variant(mutate)))


@pytest.mark.parametrize("duration", ["PT1H", "PT8H", "PT12H", "PT1H30M"])
def test_accepts_valid_session_duration(duration):
    doc = variant(lambda d: d["mappings"][0]["permission_set"].update(session_duration=duration))
    assert parse_mapping(doc).mappings[0].session_duration == duration


def test_reports_every_problem_at_once():
    def mutate(d):
        d["version"] = 9
        d["mappings"][0]["permission_set"]["name"] = ""
        d["mappings"][0]["permission_set"]["managed_policies"] = ["nope"]

    assert len(problems_for(variant(mutate))) >= 3


def test_load_rejects_invalid_json(tmp_path):
    bad = tmp_path / "mapping.json"
    bad.write_text("{not json")
    with pytest.raises(MappingError):
        load_mapping(bad)


def test_load_rejects_missing_file(tmp_path):
    with pytest.raises(MappingError):
        load_mapping(tmp_path / "missing.json")


def test_load_reads_a_valid_file(tmp_path):
    good = tmp_path / "mapping.json"
    good.write_text(json.dumps(GOOD))
    assert load_mapping(good).mappings[0].group == "AWS-IT-ReadOnly"


def test_watch_prefix_is_optional_and_defaults_to_empty():
    assert parse_mapping(GOOD).watch_prefix == ""


def test_watch_prefix_is_read():
    assert parse_mapping(variant(lambda d: d.update(watch_group_prefix="AWS-IT-"))).watch_prefix == "AWS-IT-"


def test_rejects_non_string_watch_prefix():
    assert any("watch_group_prefix" in p for p in problems_for(variant(lambda d: d.update(watch_group_prefix=5))))
