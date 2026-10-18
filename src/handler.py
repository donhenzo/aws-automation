"""Lambda entrypoint. DRY_RUN defaults to true; only the string "false" turns real changes on."""
from __future__ import annotations

import json
import logging
import os

import boto3

from mapping import MappingError, load_mapping
from reconciler import Reconciler

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    dry_run = os.environ.get("DRY_RUN", "true").strip().lower() != "false"
    path = os.environ.get("MAPPING_PATH", os.path.join(os.path.dirname(__file__), "mapping.json"))

    try:
        mapping = load_mapping(path)
    except MappingError as exc:
        logger.error(json.dumps({"layer": 1, "severity": "error", "code": "MAPPING_INVALID", "problems": exc.problems}))
        raise  # fail the invocation so the error alarm fires; never run on a bad file

    sso_admin = boto3.client("sso-admin")
    identity_store = boto3.client("identitystore")
    instances = sso_admin.list_instances()["Instances"]
    if not instances:
        raise RuntimeError("No IAM Identity Center instance found in this region")
    instance = instances[0]
    account_id = boto3.client("sts").get_caller_identity()["Account"]

    reconciler = Reconciler(
        sso_admin=sso_admin,
        identity_store=identity_store,
        instance_arn=instance["InstanceArn"],
        identity_store_id=instance["IdentityStoreId"],
        account_id=account_id,
        mapping=mapping,
        dry_run=dry_run,
    )
    findings = reconciler.run()
    for finding in findings:
        logger.info(json.dumps(finding))

    summary = {
        "code": "RUN_SUMMARY",
        "dry_run": dry_run,
        "groups_in_mapping": len(mapping.mappings),
        "errors": sum(1 for f in findings if f["severity"] == "error"),
        "warnings": sum(1 for f in findings if f["severity"] == "warning"),
    }
    logger.info(json.dumps(summary))
    return summary
