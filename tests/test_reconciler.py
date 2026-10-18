import copy

import pytest

from mapping import parse_mapping
from reconciler import Reconciler

INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-1111"
STORE_ID = "d-1111111111"
ACCOUNT = "123456789012"
RO_POLICY = "arn:aws:iam::aws:policy/ReadOnlyAccess"
TAG = {"Key": "managed-by", "Value": "henz-iga"}


class FakeClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeIdentityStore:
    def __init__(self, groups=None):
        self.groups = dict(groups or {})  # displayName -> group id

    def get_group_id(self, IdentityStoreId, AlternateIdentifier):
        name = AlternateIdentifier["UniqueAttribute"]["AttributeValue"]
        if name not in self.groups:
            raise FakeClientError("ResourceNotFoundException")
        return {"GroupId": self.groups[name]}


class FakeSSO:
    def __init__(self):
        self.permission_sets = {}  # arn -> {"Name", "Tags", "Policies"}
        self.assignments = []
        self.calls = []
        self.final_status = "SUCCEEDED"
        self.fail_create_for = None
        self._requests = {}
        self._counter = 0

    # ---- reads
    def list_permission_sets(self, InstanceArn, NextToken=None):
        self.calls.append("list_permission_sets")
        return {"PermissionSets": list(self.permission_sets)}

    def describe_permission_set(self, InstanceArn, PermissionSetArn):
        return {"PermissionSet": {"Name": self.permission_sets[PermissionSetArn]["Name"]}}

    def list_tags_for_resource(self, InstanceArn, ResourceArn, NextToken=None):
        return {"Tags": list(self.permission_sets[ResourceArn]["Tags"])}

    def list_managed_policies_in_permission_set(self, InstanceArn, PermissionSetArn, NextToken=None):
        policies = self.permission_sets[PermissionSetArn]["Policies"]
        return {"AttachedManagedPolicies": [{"Name": p.split("/")[-1], "Arn": p} for p in sorted(policies)]}

    def list_account_assignments(self, InstanceArn, AccountId, PermissionSetArn, NextToken=None):
        return {"AccountAssignments": [
            a for a in self.assignments
            if a["AccountId"] == AccountId and a["PermissionSetArn"] == PermissionSetArn
        ]}

    def describe_account_assignment_creation_status(self, InstanceArn, AccountAssignmentCreationRequestId):
        info = {"Status": self.final_status, "RequestId": AccountAssignmentCreationRequestId}
        if self.final_status == "FAILED":
            info["FailureReason"] = "simulated failure"
        return {"AccountAssignmentCreationStatus": info}

    # ---- writes (every one is recorded so tests can prove "nothing changed")
    def create_permission_set(self, Name, InstanceArn, SessionDuration, Tags, Description=None):
        self.calls.append("create_permission_set")
        if Name == self.fail_create_for:
            raise RuntimeError("simulated AWS outage")
        self._counter += 1
        arn = f"arn:aws:sso:::permissionSet/ssoins-1111/ps-{self._counter}"
        self.permission_sets[arn] = {"Name": Name, "Tags": list(Tags), "Policies": set()}
        return {"PermissionSet": {"PermissionSetArn": arn}}

    def attach_managed_policy_to_permission_set(self, InstanceArn, PermissionSetArn, ManagedPolicyArn):
        self.calls.append("attach_managed_policy_to_permission_set")
        self.permission_sets[PermissionSetArn]["Policies"].add(ManagedPolicyArn)

    def provision_permission_set(self, InstanceArn, PermissionSetArn, TargetType):
        self.calls.append("provision_permission_set")

    def create_account_assignment(self, InstanceArn, TargetId, TargetType, PermissionSetArn, PrincipalType, PrincipalId):
        self.calls.append("create_account_assignment")
        self._counter += 1
        if self.final_status == "SUCCEEDED":
            self.assignments.append({
                "AccountId": TargetId, "PermissionSetArn": PermissionSetArn,
                "PrincipalType": PrincipalType, "PrincipalId": PrincipalId,
            })
        return {"AccountAssignmentCreationStatus": {"Status": "IN_PROGRESS", "RequestId": f"req-{self._counter}"}}

    def write_calls(self):
        return [c for c in self.calls if c != "list_permission_sets"]


def mapping_doc(*groups):
    """groups: (group name, permission set name) pairs."""
    return {
        "version": 1,
        "managed_tag": {"key": "managed-by", "value": "henz-iga"},
        "mappings": [
            {"group": g, "permission_set": {"name": ps, "description": "d", "session_duration": "PT8H",
                                            "managed_policies": [RO_POLICY]}}
            for g, ps in groups
        ],
    }


def make(sso, ids, doc, dry_run=False):
    return Reconciler(
        sso_admin=sso, identity_store=ids, instance_arn=INSTANCE_ARN, identity_store_id=STORE_ID,
        account_id=ACCOUNT, mapping=parse_mapping(doc), dry_run=dry_run,
        sleep=lambda s: None, poll_attempts=3,
    )


def codes(findings):
    return [f["code"] for f in findings]


def add_owned_set(sso, name="Henz-IT-ReadOnly", policies=(RO_POLICY,)):
    sso._counter += 1
    arn = f"arn:aws:sso:::permissionSet/ssoins-1111/ps-pre{sso._counter}"
    sso.permission_sets[arn] = {"Name": name, "Tags": [TAG], "Policies": set(policies)}
    return arn


# --------------------------------------------------------------------- the happy path

def test_group_not_present_changes_nothing():
    sso, ids = FakeSSO(), FakeIdentityStore()
    findings = make(sso, ids, mapping_doc(("AWS-IT-ReadOnly", "Henz-IT-ReadOnly"))).run()
    assert codes(findings) == ["GROUP_NOT_PRESENT"]
    assert sso.write_calls() == []


def test_new_group_gets_permission_set_policy_and_assignment():
    sso, ids = FakeSSO(), FakeIdentityStore({"AWS-IT-ReadOnly": "grp-1"})
    findings = make(sso, ids, mapping_doc(("AWS-IT-ReadOnly", "Henz-IT-ReadOnly"))).run()

    assert codes(findings) == ["PERMISSION_SET_CREATED", "POLICY_ATTACHED", "ASSIGNMENT_CREATED"]
    (arn, ps), = sso.permission_sets.items()
    assert ps["Name"] == "Henz-IT-ReadOnly"
    assert TAG in ps["Tags"]  # tagged so we can prove ownership later
    assert ps["Policies"] == {RO_POLICY}
    assert sso.assignments == [{"AccountId": ACCOUNT, "PermissionSetArn": arn,
                                "PrincipalType": "GROUP", "PrincipalId": "grp-1"}]


def test_second_run_changes_nothing_idempotent():
    sso, ids = FakeSSO(), FakeIdentityStore({"AWS-IT-ReadOnly": "grp-1"})
    doc = mapping_doc(("AWS-IT-ReadOnly", "Henz-IT-ReadOnly"))
    make(sso, ids, doc).run()
    writes_after_first = len(sso.write_calls())

    findings = make(sso, ids, doc).run()
    assert len(sso.write_calls()) == writes_after_first  # no new write calls at all
    assert codes(findings) == ["ASSIGNMENT_OK"]
    assert len(sso.assignments) == 1


# --------------------------------------------------------------------------- dry run

def test_dry_run_reports_but_changes_nothing():
    sso, ids = FakeSSO(), FakeIdentityStore({"AWS-IT-ReadOnly": "grp-1"})
    findings = make(sso, ids, mapping_doc(("AWS-IT-ReadOnly", "Henz-IT-ReadOnly")), dry_run=True).run()
    assert codes(findings) == ["WOULD_CREATE_PERMISSION_SET", "WOULD_ASSIGN"]
    assert sso.write_calls() == []
    assert sso.permission_sets == {} and sso.assignments == []
    assert all(f["dry_run"] for f in findings)


def test_dry_run_on_existing_set_reports_missing_policy_and_assignment():
    sso, ids = FakeSSO(), FakeIdentityStore({"AWS-IT-ReadOnly": "grp-1"})
    add_owned_set(sso, policies=())
    findings = make(sso, ids, mapping_doc(("AWS-IT-ReadOnly", "Henz-IT-ReadOnly")), dry_run=True).run()
    assert codes(findings) == ["WOULD_ATTACH_POLICY", "WOULD_ASSIGN"]
    assert sso.write_calls() == []


# ------------------------------------------------- checks that must be able to FAIL

def test_refuses_to_touch_a_permission_set_we_do_not_own():
    sso, ids = FakeSSO(), FakeIdentityStore({"AWS-IT-ReadOnly": "grp-1"})
    arn = add_owned_set(sso)
    sso.permission_sets[arn]["Tags"] = []  # same name, but someone else's
    findings = make(sso, ids, mapping_doc(("AWS-IT-ReadOnly", "Henz-IT-ReadOnly"))).run()
    assert codes(findings) == ["PERMISSION_SET_NOT_OWNED"]
    assert findings[0]["severity"] == "error"
    assert sso.write_calls() == []
    assert sso.assignments == []


def test_wrong_tag_value_also_counts_as_not_owned():
    sso, ids = FakeSSO(), FakeIdentityStore({"AWS-IT-ReadOnly": "grp-1"})
    arn = add_owned_set(sso)
    sso.permission_sets[arn]["Tags"] = [{"Key": "managed-by", "Value": "someone-else"}]
    findings = make(sso, ids, mapping_doc(("AWS-IT-ReadOnly", "Henz-IT-ReadOnly"))).run()
    assert codes(findings) == ["PERMISSION_SET_NOT_OWNED"]


def test_assignment_failure_is_reported_as_error():
    sso, ids = FakeSSO(), FakeIdentityStore({"AWS-IT-ReadOnly": "grp-1"})
    sso.final_status = "FAILED"
    findings = make(sso, ids, mapping_doc(("AWS-IT-ReadOnly", "Henz-IT-ReadOnly"))).run()
    failed = [f for f in findings if f["code"] == "ASSIGNMENT_FAILED"]
    assert failed and failed[0]["severity"] == "error"
    assert "simulated failure" in failed[0]["message"]


def test_success_without_a_visible_assignment_is_caught_by_layer_two():
    class Liar(FakeSSO):
        def create_account_assignment(self, **kwargs):
            self.calls.append("create_account_assignment")
            return {"AccountAssignmentCreationStatus": {"Status": "IN_PROGRESS", "RequestId": "req-x"}}

    sso, ids = Liar(), FakeIdentityStore({"AWS-IT-ReadOnly": "grp-1"})
    findings = make(sso, ids, mapping_doc(("AWS-IT-ReadOnly", "Henz-IT-ReadOnly"))).run()
    assert "ASSIGNMENT_NOT_VISIBLE" in codes(findings)


def test_assignment_still_in_progress_is_a_warning_not_a_success():
    sso, ids = FakeSSO(), FakeIdentityStore({"AWS-IT-ReadOnly": "grp-1"})
    sso.final_status = "IN_PROGRESS"
    findings = make(sso, ids, mapping_doc(("AWS-IT-ReadOnly", "Henz-IT-ReadOnly"))).run()
    assert "ASSIGNMENT_PENDING" in codes(findings)
    assert "ASSIGNMENT_CREATED" not in codes(findings)


def test_extra_policy_is_reported_but_not_reverted_yet():
    sso, ids = FakeSSO(), FakeIdentityStore({"AWS-IT-ReadOnly": "grp-1"})
    extra = "arn:aws:iam::aws:policy/AdministratorAccess"
    arn = add_owned_set(sso, policies=(RO_POLICY, extra))
    findings = make(sso, ids, mapping_doc(("AWS-IT-ReadOnly", "Henz-IT-ReadOnly"))).run()
    drift = [f for f in findings if f["code"] == "POLICY_DRIFT"]
    assert drift and drift[0]["layer"] == 3 and extra in drift[0]["message"]
    assert extra in sso.permission_sets[arn]["Policies"]  # reported only


def test_missing_policy_on_existing_set_is_attached_and_provisioned():
    sso, ids = FakeSSO(), FakeIdentityStore({"AWS-IT-ReadOnly": "grp-1"})
    arn = add_owned_set(sso, policies=())
    make(sso, ids, mapping_doc(("AWS-IT-ReadOnly", "Henz-IT-ReadOnly"))).run()
    assert sso.permission_sets[arn]["Policies"] == {RO_POLICY}
    assert "provision_permission_set" in sso.calls


# --------------------------------------------------------------- failure isolation

def test_one_group_failing_does_not_block_the_next():
    sso = FakeSSO()
    sso.fail_create_for = "Henz-IT-Broken"
    ids = FakeIdentityStore({"AWS-IT-Broken": "grp-1", "AWS-IT-ReadOnly": "grp-2"})
    doc = mapping_doc(("AWS-IT-Broken", "Henz-IT-Broken"), ("AWS-IT-ReadOnly", "Henz-IT-ReadOnly"))
    findings = make(sso, ids, doc).run()

    assert any(f["code"] == "UNEXPECTED_ERROR" and f["group"] == "AWS-IT-Broken" for f in findings)
    assert any(f["code"] == "ASSIGNMENT_CREATED" and f["group"] == "AWS-IT-ReadOnly" for f in findings)


def test_unexpected_identity_store_error_is_reported_not_swallowed():
    class BrokenStore(FakeIdentityStore):
        def get_group_id(self, **kwargs):
            raise FakeClientError("AccessDeniedException")

    findings = make(FakeSSO(), BrokenStore(), mapping_doc(("AWS-IT-ReadOnly", "Henz-IT-ReadOnly"))).run()
    assert codes(findings) == ["UNEXPECTED_ERROR"]
    assert "AccessDeniedException" in findings[0]["message"]
