"""Load and validate the group -> permission set mapping file.

Validation layer 1 (file part): the file is well formed and strictly 1:1 (ADR-010).
Every problem is collected, so one run shows everything that is wrong.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

SUPPORTED_VERSION = 1

# AWS limits: permission set name 1-32 chars from this set; session 1h-12h.
PERMISSION_SET_NAME_RE = re.compile(r"^[\w+=,.@-]{1,32}$")
# v1 allows AWS managed policies only (no customer managed, no inline).
MANAGED_POLICY_ARN_RE = re.compile(r"^arn:aws:iam::aws:policy/[\w+=,.@/-]+$")
DURATION_RE = re.compile(r"^PT(?:(?P<h>\d{1,2})H)?(?:(?P<m>\d{1,2})M)?$")


class MappingError(Exception):
    """Raised when the mapping file is invalid. `problems` lists every issue found."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("; ".join(problems))


@dataclass(frozen=True)
class Mapping:
    group: str
    permission_set_name: str
    description: str
    session_duration: str
    managed_policies: tuple[str, ...]


@dataclass(frozen=True)
class MappingFile:
    managed_tag_key: str
    managed_tag_value: str
    mappings: tuple[Mapping, ...]


def _nonempty_str(value: object) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _duration_ok(value: str) -> bool:
    match = DURATION_RE.match(value)
    if not match:
        return False
    minutes = int(match.group("h") or 0) * 60 + int(match.group("m") or 0)
    return 60 <= minutes <= 720


def _parse_entry(where: str, item: object, problems: list[str]) -> Mapping | None:
    start = len(problems)
    if not isinstance(item, dict):
        problems.append(f"{where}: must be an object")
        return None

    group = item.get("group")
    if not _nonempty_str(group):
        problems.append(f"{where}.group: must be a non-empty string")

    ps = item.get("permission_set")
    if not isinstance(ps, dict):
        problems.append(f"{where}.permission_set: must be an object")
        return None

    name = ps.get("name")
    if not isinstance(name, str) or not PERMISSION_SET_NAME_RE.match(name):
        problems.append(f"{where}.permission_set.name: must be 1-32 characters from [A-Za-z0-9_+=,.@-]")

    description = ps.get("description", "")
    if not isinstance(description, str) or len(description) > 700:
        problems.append(f"{where}.permission_set.description: must be a string of at most 700 characters")

    duration = ps.get("session_duration", "PT8H")
    if not isinstance(duration, str) or not _duration_ok(duration):
        problems.append(f"{where}.permission_set.session_duration: must be ISO 8601 between PT1H and PT12H")

    policies = ps.get("managed_policies")
    if not isinstance(policies, list) or not policies:
        problems.append(f"{where}.permission_set.managed_policies: must be a non-empty list")
        policies = []
    for arn in policies:
        if not isinstance(arn, str) or not MANAGED_POLICY_ARN_RE.match(arn):
            problems.append(f"{where}.permission_set.managed_policies: {arn!r} is not an AWS managed policy ARN")
    if len(set(policies)) != len(policies):
        problems.append(f"{where}.permission_set.managed_policies: contains duplicates")

    if len(problems) > start:
        return None
    return Mapping(
        group=group.strip(),
        permission_set_name=name,
        description=description,
        session_duration=duration,
        managed_policies=tuple(policies),
    )


def _check_one_to_one(entries: list[Mapping], problems: list[str]) -> None:
    seen_groups: dict[str, str] = {}
    seen_sets: dict[str, str] = {}
    for entry in entries:
        group_key = entry.group.lower()
        if group_key in seen_groups:
            problems.append(f"group {entry.group!r} appears more than once")
        seen_groups[group_key] = entry.group
        set_key = entry.permission_set_name.lower()
        if set_key in seen_sets:
            problems.append(
                f"permission set {entry.permission_set_name!r} is used by more than one group "
                f"({seen_sets[set_key]!r} and {entry.group!r}); ADR-010 requires 1:1"
            )
        seen_sets[set_key] = entry.group


def parse_mapping(doc: object) -> MappingFile:
    if not isinstance(doc, dict):
        raise MappingError(["mapping file must be a JSON object"])

    problems: list[str] = []
    if doc.get("version") != SUPPORTED_VERSION:
        problems.append(f"version must be {SUPPORTED_VERSION}, got {doc.get('version')!r}")

    tag = doc.get("managed_tag")
    tag_key = tag_value = ""
    if isinstance(tag, dict) and _nonempty_str(tag.get("key")) and _nonempty_str(tag.get("value")):
        tag_key, tag_value = tag["key"], tag["value"]
    else:
        problems.append("managed_tag must have a non-empty 'key' and 'value'")

    raw = doc.get("mappings")
    if not isinstance(raw, list) or not raw:
        problems.append("mappings must be a non-empty list")
        raw = []

    entries: list[Mapping] = []
    for index, item in enumerate(raw):
        entry = _parse_entry(f"mappings[{index}]", item, problems)
        if entry is not None:
            entries.append(entry)
    _check_one_to_one(entries, problems)

    if problems:
        raise MappingError(problems)
    return MappingFile(tag_key, tag_value, tuple(entries))


def load_mapping(path: str | Path) -> MappingFile:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise MappingError([f"mapping file not found: {path}"]) from None
    except json.JSONDecodeError as exc:
        raise MappingError([f"mapping file is not valid JSON: {exc}"]) from None
    return parse_mapping(doc)
