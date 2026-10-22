# Run ONCE by hand (from CloudShell). It lets GitHub Actions deploy without any stored keys.
# After this, every change goes through the pipeline.

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60, < 7.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project   = "henz-iga"
      terraform = "true"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id       = data.aws_caller_identity.current.account_id
  prefix           = var.name_prefix
  state_bucket_arn = "arn:aws:s3:::${var.state_bucket}"
}

# GitHub proves who it is with a short-lived token; AWS checks it against this provider.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # AWS no longer relies on this value for GitHub, but older provider versions require one.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

# ------------------------------------------------------------------ plan role (read only)
# Used on pull requests and for the plan step on main.
data "aws_iam_policy_document" "plan_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_repo}:pull_request",
        "repo:${var.github_repo}:ref:refs/heads/main",
      ]
    }
  }
}

resource "aws_iam_role" "plan" {
  name                 = "henz-cicd-plan"
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "plan_read" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# apply role
# Only the 'production' environment (which needs your approval) can assume this one.
data "aws_iam_policy_document" "apply_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:environment:production"]
    }
  }
}

resource "aws_iam_role" "apply" {
  name                 = "henz-cicd-apply"
  assume_role_policy   = data.aws_iam_policy_document.apply_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "apply_read" {
  role       = aws_iam_role.apply.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Write access is limited to resources named henz-iga-*, in this region and account.
# Known residual risk: this role can write policies on henz-iga-* roles, so the approval step
# on the production environment is what guards it. A permissions boundary is on the backlog.
data "aws_iam_policy_document" "apply" {
  statement {
    sid       = "StateBucket"
    actions   = ["s3:ListBucket"]
    resources = [local.state_bucket_arn]
  }
  statement {
    sid     = "StateObject"
    actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = [
      "${local.state_bucket_arn}/henz-iga/terraform.tfstate",
      "${local.state_bucket_arn}/henz-iga/terraform.tfstate.tflock",
    ]
  }
  statement {
    sid       = "Lambda"
    actions   = ["lambda:*"]
    resources = ["arn:aws:lambda:${var.region}:${local.account_id}:function:${local.prefix}-*"]
  }
  statement {
    sid = "IamRoles"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:UpdateRole", "iam:UpdateAssumeRolePolicy",
      "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy",
      "iam:TagRole", "iam:UntagRole",
    ]
    resources = ["arn:aws:iam::${local.account_id}:role/${local.prefix}-*"]
  }
  statement {
    sid       = "PassRoleToLambdaOnly"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${local.account_id}:role/${local.prefix}-*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }
  statement {
    sid = "Events"
    actions = [
      "events:PutRule", "events:DeleteRule", "events:EnableRule", "events:DisableRule",
      "events:PutTargets", "events:RemoveTargets", "events:TagResource", "events:UntagResource",
    ]
    resources = ["arn:aws:events:${var.region}:${local.account_id}:rule/${local.prefix}-*"]
  }
  statement {
    sid = "Logs"
    actions = [
      "logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:DeleteRetentionPolicy",
      "logs:TagResource", "logs:UntagResource", "logs:TagLogGroup", "logs:UntagLogGroup",
    ]
    resources = [
      "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/${local.prefix}-*",
      "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/${local.prefix}-*:*",
    ]
  }
  statement {
    sid       = "Alarms"
    actions   = ["cloudwatch:PutMetricAlarm", "cloudwatch:DeleteAlarms", "cloudwatch:TagResource", "cloudwatch:UntagResource"]
    resources = ["arn:aws:cloudwatch:${var.region}:${local.account_id}:alarm:${local.prefix}-*"]
  }
  statement {
    sid = "Sns"
    actions = [
      "sns:CreateTopic", "sns:DeleteTopic", "sns:SetTopicAttributes", "sns:Subscribe", "sns:Unsubscribe",
      "sns:TagResource", "sns:UntagResource",
    ]
    resources = ["arn:aws:sns:${var.region}:${local.account_id}:${local.prefix}-*"]
  }
  statement {
    sid       = "DynamoDb"
    actions   = ["dynamodb:*"]
    resources = ["arn:aws:dynamodb:${var.region}:${local.account_id}:table/${local.prefix}-*"]
  }
}

resource "aws_iam_role_policy" "apply" {
  name   = "terraform-apply"
  role   = aws_iam_role.apply.id
  policy = data.aws_iam_policy_document.apply.json
}
