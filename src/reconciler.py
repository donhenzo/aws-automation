"""Reconciler: make IAM Identity Center match the mapping file.

Each run, for every mapped group that exists in the identity store:
  1. (layer 1) refuse to touch a permission set we do not own (no tag);
  2. create the permission set if missing, attach the declared policies;
  3. assign the permission set to the group on the account if not already assigned;
  4. (layer 2) wait for the assignment and confirm it is really there.
Anything that does not match the file but is not fixed yet (extra policies) is reported
as a layer 3 finding. Auto-revert comes in a later phase.

Safe to run repeatedly. Dry-run reads everything and changes nothing.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Iterator

from mapping import Mapping, MappingFile


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if code:
            return code
    return type(exc).__name__


class Reconciler:
    def __init__(
        self,
        *,
        sso_admin: Any,
        identity_store: Any,
        instance_arn: str,
        identity_store_id: str,
        account_id: str,
        mapping: MappingFile,
        dry_run: bool = True,
        sleep: Callable[[float], None] = time.sleep,
        poll_attempts: int = 10,
        poll_seconds: float = 2.0,
    ):
        self.sso = sso_admin
        self.ids = identity_store
        self.instance_arn = instance_arn
        self.identity_store_id = identity_store_id
        self.account_id = account_id
        self.mapping = mapping
        self.dry_run = dry_run
        self._sleep = sleep
        self._poll_attempts = poll_attempts
        self._poll_seconds = poll_seconds
        self.findings: list[dict[str, Any]] = []


    def run(self) -> list[dict[str, Any]]:
        self.findings = []
        try:
            by_name = self._permission_sets_by_name()
        except Exception as exc:  # cannot even read state: report and stop
            self._add(1, "error", "LIST_PERMISSION_SETS_FAILED", "*", f"{_error_code(exc)}: {exc}")
            return self.findings

        for entry in self.mapping.mappings:
            try:
                self._reconcile_group(entry, by_name)
            except Exception as exc:  # one group failing must not block the others
                self._add(1, "error", "UNEXPECTED_ERROR", entry.group, f"{_error_code(exc)}: {exc}")
        return self.findings

    def _reconcile_group(self, entry: Mapping, by_name: dict[str, str]) -> None:
        group_id = self._group_id(entry.group)
        if group_id is None:
            self._add(1, "info", "GROUP_NOT_PRESENT", entry.group, "Group is not in the identity store yet; nothing to do.")
            return

        ps_arn = by_name.get(entry.permission_set_name)
        preexisting = ps_arn is not None

        if ps_arn is None:
            if self.dry_run:
                self._add(1, "info", "WOULD_CREATE_PERMISSION_SET", entry.group,
                          f"Would create permission set {entry.permission_set_name}.", "dry-run")
                self._add(2, "info", "WOULD_ASSIGN", entry.group,
                          f"Would assign {entry.permission_set_name} to the group on account {self.account_id}.", "dry-run")
                return
            ps_arn = self._create_permission_set(entry)
        elif not self._is_owned(ps_arn):
            self._add(1, "error", "PERMISSION_SET_NOT_OWNED", entry.group,
                      f"A permission set named {entry.permission_set_name} exists but does not carry the "
                      f"{self.mapping.managed_tag_key}={self.mapping.managed_tag_value} tag. Refusing to touch it.")
            return

        self._ensure_policies(entry, ps_arn, preexisting)
        self._ensure_assignment(entry, ps_arn, group_id)

    # permission set

    def _create_permission_set(self, entry: Mapping) -> str:
        kwargs: dict[str, Any] = {
            "Name": entry.permission_set_name,
            "InstanceArn": self.instance_arn,
            "SessionDuration": entry.session_duration,
            "Tags": [{"Key": self.mapping.managed_tag_key, "Value": self.mapping.managed_tag_value}],
        }
        if entry.description:
            kwargs["Description"] = entry.description
        arn = self.sso.create_permission_set(**kwargs)["PermissionSet"]["PermissionSetArn"]
        self._add(2, "info", "PERMISSION_SET_CREATED", entry.group,
                  f"Created permission set {entry.permission_set_name}.", "created")
        return arn

    def _ensure_policies(self, entry: Mapping, ps_arn: str, preexisting: bool) -> None:
        attached = {
            p["Arn"]
            for p in self._paginate(
                self.sso.list_managed_policies_in_permission_set, "AttachedManagedPolicies",
                InstanceArn=self.instance_arn, PermissionSetArn=ps_arn,
            )
        }
        declared = set(entry.managed_policies)

        attached_now = False
        for arn in sorted(declared - attached):
            if self.dry_run:
                self._add(2, "info", "WOULD_ATTACH_POLICY", entry.group, f"Would attach {arn}.", "dry-run")
                continue
            self.sso.attach_managed_policy_to_permission_set(
                InstanceArn=self.instance_arn, PermissionSetArn=ps_arn, ManagedPolicyArn=arn)
            attached_now = True
            self._add(2, "info", "POLICY_ATTACHED", entry.group, f"Attached {arn}.", "attached")

        # A policy added to a permission set that is already assigned must be pushed to the accounts.
        if attached_now and preexisting:
            self.sso.provision_permission_set(
                InstanceArn=self.instance_arn, PermissionSetArn=ps_arn, TargetType="ALL_PROVISIONED_ACCOUNTS")

        extra = sorted(attached - declared)
        if extra:
            self._add(3, "warning", "POLICY_DRIFT", entry.group,
                      f"Policies on {entry.permission_set_name} that the file does not declare: {', '.join(extra)}. "
                      "Reported only; auto-revert is a later phase.")

    # assignment

    def _assignment_exists(self, ps_arn: str, group_id: str) -> bool:
        return any(
            a.get("PrincipalType") == "GROUP" and a.get("PrincipalId") == group_id
            for a in self._paginate(
                self.sso.list_account_assignments, "AccountAssignments",
                InstanceArn=self.instance_arn, AccountId=self.account_id, PermissionSetArn=ps_arn,
            )
        )

    def _ensure_assignment(self, entry: Mapping, ps_arn: str, group_id: str) -> None:
        if self._assignment_exists(ps_arn, group_id):
            self._add(2, "info", "ASSIGNMENT_OK", entry.group,
                      f"{entry.permission_set_name} is already assigned to the group.")
            return
        if self.dry_run:
            self._add(2, "info", "WOULD_ASSIGN", entry.group,
                      f"Would assign {entry.permission_set_name} to the group on account {self.account_id}.", "dry-run")
            return

        resp = self.sso.create_account_assignment(
            InstanceArn=self.instance_arn, TargetId=self.account_id, TargetType="AWS_ACCOUNT",
            PermissionSetArn=ps_arn, PrincipalType="GROUP", PrincipalId=group_id)
        request_id = resp["AccountAssignmentCreationStatus"]["RequestId"]
        status, reason = self._wait_for_assignment(request_id)

        if status == "SUCCEEDED":
            if self._assignment_exists(ps_arn, group_id):  # layer 2: confirm it really landed
                self._add(2, "info", "ASSIGNMENT_CREATED", entry.group,
                          f"Assigned {entry.permission_set_name} to the group on account {self.account_id}.", "created")
            else:
                self._add(2, "error", "ASSIGNMENT_NOT_VISIBLE", entry.group,
                          "AWS reported success but the assignment is not listed.")
        elif status == "FAILED":
            self._add(2, "error", "ASSIGNMENT_FAILED", entry.group, f"AWS could not create the assignment: {reason}")
        else:
            self._add(2, "warning", "ASSIGNMENT_PENDING", entry.group,
                      "Assignment still in progress when the wait ended; the next run will confirm it.")

    def _wait_for_assignment(self, request_id: str) -> tuple[str, str]:
        status, reason = "IN_PROGRESS", ""
        for attempt in range(self._poll_attempts):
            info = self.sso.describe_account_assignment_creation_status(
                InstanceArn=self.instance_arn, AccountAssignmentCreationRequestId=request_id,
            )["AccountAssignmentCreationStatus"]
            status, reason = info["Status"], info.get("FailureReason", "")
            if status != "IN_PROGRESS":
                break
            if attempt < self._poll_attempts - 1:
                self._sleep(self._poll_seconds)
        return status, reason

    # lookups

    def _group_id(self, name: str) -> str | None:
        try:
            resp = self.ids.get_group_id(
                IdentityStoreId=self.identity_store_id,
                AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": name}},
            )
        except Exception as exc:
            if _error_code(exc) == "ResourceNotFoundException":
                return None
            raise
        return resp["GroupId"]

    def _permission_sets_by_name(self) -> dict[str, str]:
        by_name: dict[str, str] = {}
        for arn in self._paginate(self.sso.list_permission_sets, "PermissionSets", InstanceArn=self.instance_arn):
            described = self.sso.describe_permission_set(InstanceArn=self.instance_arn, PermissionSetArn=arn)
            by_name[described["PermissionSet"]["Name"]] = arn
        return by_name

    def _is_owned(self, ps_arn: str) -> bool:
        tags = self._paginate(self.sso.list_tags_for_resource, "Tags",
                              InstanceArn=self.instance_arn, ResourceArn=ps_arn)
        return any(
            t.get("Key") == self.mapping.managed_tag_key and t.get("Value") == self.mapping.managed_tag_value
            for t in tags
        )

    # helpers

    @staticmethod
    def _paginate(fn: Callable[..., dict], key: str, **kwargs: Any) -> Iterator[Any]:
        token = None
        while True:
            resp = fn(**kwargs, **({"NextToken": token} if token else {}))
            yield from resp.get(key, [])
            token = resp.get("NextToken")
            if not token:
                return

    def _add(self, layer: int, severity: str, code: str, group: str, message: str, action: str = "none") -> None:
        self.findings.append({
            "layer": layer, "severity": severity, "code": code, "group": group,
            "message": message, "action": action, "dry_run": self.dry_run,
        })
