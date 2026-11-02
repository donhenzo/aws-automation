# Henz IGA: automatic AWS access assignment

When a group appears in AWS IAM Identity Center, the right access is attached to it automatically, safely, and with a record of what happened.

**Status:** working end to end for three groups in a lab account, deployed through a CI/CD pipeline. Not production yet.

## The problem

Companies manage people and groups in one place (here Microsoft Entra ID) and use AWS IAM Identity Center as the front door to AWS. A tool called SCIM copies users and groups into AWS, but a copied group can do nothing. An admin must still open the console and link the group to a **permission set** (a bundle of permissions) on an AWS account. That link is called an **assignment**, and SCIM does not create it.

Done by hand, this is slow (a new engineer waits for a ticket), inconsistent, easy to get wrong, and nobody can check the result against a written rule.

## The solution

A small program, the **reconciler**, holds a rule book. Every 5 minutes it looks at the groups in AWS and, for each group in the rule book, makes sure the right permission set exists and is assigned. If everything already matches, it does nothing.

It does not matter how a group got into AWS (SCIM, a script, Terraform). The rule is: group created, access follows.

```
  SCIM / script / Terraform  -->  groups in IAM Identity Center
                                          |   every 5 minutes
  mapping/mapping.json  -------->  RECONCILER (AWS Lambda, Python)
  (the rule book)                   - checks the rule book
                                    - creates the permission set if missing
                                    - assigns it to the group
                                    - confirms the assignment exists
                                          |
                                  logs + error alarm
```

## The rule book

`mapping/mapping.json` says which group gets which permission set:

```json
{
  "group": "AWS-IT-ReadOnly",
  "permission_set": {
    "name": "Henz-IT-ReadOnly",
    "session_duration": "PT8H",
    "managed_policies": ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
  }
}
```

- Rules are matched by group **name**, so a group re-created later still matches.
- The automation creates the permission set itself. You do not create it by hand.
- One group, one permission set. The file is rejected if two groups share one.
- A group that starts with the watched prefix (`AWS-IT-`) but has no rule raises a warning, so a typo is not silent.

## Safety

- **Dry run** mode reports what it would do and changes nothing.
- The rule book is validated before anything is touched.
- After assigning, it re-reads AWS to confirm the assignment is really there.
- It only edits permission sets it created (they carry a `managed-by` tag) and refuses the rest.
- Running it twice changes nothing. One failing rule never blocks the others.
- Any error fails the run and trips an alarm.
- It assigns on a member account, not the management account, because assigning into the management account needs IAM-admin power.

## Changing something

Every change goes through GitHub, with no zip uploads and no stored AWS keys.

1. Edit on a branch and open a pull request.
2. The pipeline runs the tests, checks the mapping file, validates the Terraform, scans it, and posts a `terraform plan` on the pull request.
3. Merge to `main`. The pipeline waits for your approval on the `production` environment, runs `terraform apply`, then invokes the function once as a smoke test.

GitHub proves its identity to AWS with a short-lived token (OIDC). A one-time bootstrap in `bootstrap/` creates the two roles the pipeline uses: one read-only for plans, one for apply. Each deploy records its commit on the Lambda and publishes a numbered version.

To add a group: add a rule to `mapping/mapping.json` and open a pull request.

## What is done

- Reconciler, rule-book validation and tests (49 checks against fake AWS clients).
- Proven on real AWS: create and assign, repeat run changes nothing, an unmapped group is ignored, and a permission set the automation does not own is refused untouched.
- Runs on a 5-minute schedule. Terraform state is in S3.
- Three groups mapped: `AWS-IT-ReadOnly`, `AWS-IT-PowerUsers`, `AWS-IT-Security`.
- CI/CD pipeline deployed.

## What is next

1. A policy allow-list, then `AWS-IT-Admins`. Today anyone who can edit the mapping and merge could map a group to a powerful policy.
2. Alerts, including a notice when a new group arrives and what it was given.
3. Detect and revert permission sets or assignments changed by hand.
4. Entra SAML and SCIM (waiting on licensing), then a real user sign-in test.
5. A VM scenario: a group that can start, stop and log in to an instance.
6. Final documentation.

## Layout

```
mapping/       the rule book
src/           the reconciler (Lambda code)
infra/         Terraform for the Lambda, role, schedule and alarm
bootstrap/     one-time Terraform for the pipeline's AWS roles
scripts/       mapping check, and the Entra lab user script
tests/         automated checks
.github/       the pipeline
```
