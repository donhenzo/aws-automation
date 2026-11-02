"""Policy allow-list: which AWS managed policies the mapping file may attach.

Why: without a gate, anyone who can edit mapping.json could hand a group a powerful policy.
Three rules are enforced, in CI and again inside the Lambda (so skipping CI does not help):

  1. A policy that is not in mapping/policy-allowlist.json is rejected.
  2. A "privileged" policy needs a written justification in the mapping rule, and the
     session may not be longer than the limit set for that policy.
  3. Some policies are never allowed, whatever the file says (HARD_DENIED_POLICIES below).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from mapping import (
    MANAGED_POLICY_ARN_RE,
    MappingError,
    MappingFile,
    duration_minutes,
    load_mapping,
)

# Policies that control IAM, Organizations or Identity Center themselves. A group holding one
# of these could change who has access to everything, so no allow-list entry can override this.
HARD_DENIED_POLICIES = frozenset({
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/AWSOrganizationsFullAccess",
    "arn:aws:iam::aws:policy/AWSSSOMasterAccountAdministrator",
    "arn:aws:iam::aws:policy/AWSSSOMemberAccountAdministrator",
    "arn:aws:iam::aws:policy/AWSSSODirectoryAdministrator",
})

TIERS = ("standard", "privileged")
PRIVILEGED_MAX_MINUTES = 240          # a privileged policy can never allow a session over 4 hours
MIN_JUSTIFICATION_CHARS = 20
SUPPORTED_VERSION = 1
_TOP_LEVEL_KEYS = {"_readme", "version", "policies"}
_ENTRY_KEYS = {"tier", "max_session_duration", "reason"}


@dataclass(frozen=True)
class AllowedPolicy:
    tier: str
    max_session_minutes: int
    reason: str


@dataclass(frozen=True)
class Allowlist:
    policies: dict


def parse_allowlist(doc: object) -> Allowlist:
    if not isinstance(doc, dict):
        raise MappingError(["allow-list: file must be a JSON object"])

    problems: list[str] = []
    for key in sorted(set(doc) - _TOP_LEVEL_KEYS):
        problems.append(f"allow-list: unknown top-level key {key!r}")
    if doc.get("version") != SUPPORTED_VERSION:
        problems.append(f"allow-list: version must be {SUPPORTED_VERSION}, got {doc.get('version')!r}")

    readme = doc.get("_readme", [])
    if not isinstance(readme, list) or not all(isinstance(line, str) for line in readme):
        problems.append("allow-list: _readme must be a list of text lines")

    raw = doc.get("policies")
    if not isinstance(raw, dict) or not raw:
        problems.append("allow-list: policies must be a non-empty object")
        raw = {}

    policies: dict[str, AllowedPolicy] = {}
    for arn, entry in raw.items():
        where = f"allow-list: {arn}"
        if not MANAGED_POLICY_ARN_RE.match(arn):
            problems.append(f"{where}: key is not an AWS managed policy ARN")
            continue
        if arn in HARD_DENIED_POLICIES:
            problems.append(f"{where}: this policy is never allowed (it controls IAM, Organizations or Identity Center)")
            continue
        if not isinstance(entry, dict):
            problems.append(f"{where}: entry must be an object")
            continue
        for key in sorted(set(entry) - _ENTRY_KEYS):
            problems.append(f"{where}: unknown key {key!r}")

        tier = entry.get("tier")
        if tier not in TIERS:
            problems.append(f"{where}: tier must be 'standard' or 'privileged'")

        duration = entry.get("max_session_duration")
        minutes = duration_minutes(duration) if isinstance(duration, str) else None
        if minutes is None or not 60 <= minutes <= 720:
            problems.append(f"{where}: max_session_duration must be ISO 8601 between PT1H and PT12H")
        elif tier == "privileged" and minutes > PRIVILEGED_MAX_MINUTES:
            problems.append(f"{where}: a privileged policy cannot allow sessions longer than PT4H")

        reason = entry.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            problems.append(f"{where}: reason must explain why this policy is allowed (at least 10 characters)")

        if not any(p.startswith(where) for p in problems):
            policies[arn] = AllowedPolicy(tier, minutes, reason.strip())

    if problems:
        raise MappingError(problems)
    return Allowlist(policies)


def load_allowlist(path: str | Path) -> Allowlist:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise MappingError([f"allow-list: file not found: {path}"]) from None
    except json.JSONDecodeError as exc:
        raise MappingError([f"allow-list: not valid JSON: {exc}"]) from None
    return parse_allowlist(doc)


def check_mapping(mapping: MappingFile, allowlist: Allowlist) -> list[str]:
    """Return every way the mapping breaks the allow-list rules (empty list means it is fine)."""
    problems: list[str] = []
    for entry in mapping.mappings:
        who = f"rule for group {entry.group!r}"
        minutes = duration_minutes(entry.session_duration)
        for arn in entry.managed_policies:
            if arn in HARD_DENIED_POLICIES:
                problems.append(f"{who}: {arn} is never allowed (it controls IAM, Organizations or Identity Center)")
                continue
            allowed = allowlist.policies.get(arn)
            if allowed is None:
                problems.append(f"{who}: {arn} is not in the policy allow-list")
                continue
            if minutes is not None and minutes > allowed.max_session_minutes:
                problems.append(
                    f"{who}: session {entry.session_duration} is longer than the {allowed.max_session_minutes} "
                    f"minutes allowed for {arn}"
                )
            if allowed.tier == "privileged" and len(entry.justification) < MIN_JUSTIFICATION_CHARS:
                problems.append(
                    f"{who}: {arn} is privileged, so the rule needs a 'justification' of at least "
                    f"{MIN_JUSTIFICATION_CHARS} characters"
                )
    return problems


def load_checked_mapping(mapping_path: str | Path, allowlist_path: str | Path) -> MappingFile:
    """Load the mapping and refuse it unless it passes the allow-list. Used by CI and the Lambda."""
    mapping = load_mapping(mapping_path)
    allowlist = load_allowlist(allowlist_path)
    problems = check_mapping(mapping, allowlist)
    if problems:
        raise MappingError(problems)
    return mapping
