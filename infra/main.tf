terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60, < 7.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
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

# The existing Identity Center instance (it was enabled by hand; Terraform only reads it).
data "aws_ssoadmin_instances" "this" {}

locals {
  function_name = "henz-iga-reconciler"
  instance_arn  = tolist(data.aws_ssoadmin_instances.this.arns)[0]
  instance_id   = element(split("/", local.instance_arn), 1)
  alarm_actions = aws_sns_topic.alerts[*].arn
}

# package the code
# The mapping file ships inside the function, so a change to it is a reviewed, versioned deploy.
data "archive_file" "lambda" {
  type        = "zip"
  output_path = "${path.module}/reconciler.zip"

  source {
    content  = file("${path.module}/../src/handler.py")
    filename = "handler.py"
  }
  source {
    content  = file("${path.module}/../src/mapping.py")
    filename = "mapping.py"
  }
  source {
    content  = file("${path.module}/../src/reconciler.py")
    filename = "reconciler.py"
  }
  source {
    content  = file("${path.module}/../mapping/mapping.json")
    filename = "mapping.json"
  }
}

#logs
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 30
}

# role
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

# Least privilege, scoped to this instance, its permission sets and ONE target account.
# Hardening backlog: tag conditions, an allow-list of attachable policies, Access Analyzer checks.
data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid       = "FindTheInstance"
    actions   = ["sso:ListInstances"]
    resources = ["*"]
  }

  statement {
    sid = "ReadIdentityCenter"
    actions = [
      "sso:ListPermissionSets",
      "sso:DescribePermissionSet",
      "sso:ListTagsForResource",
      "sso:ListManagedPoliciesInPermissionSet",
      "sso:ListAccountAssignments",
      "sso:DescribeAccountAssignmentCreationStatus",
      "identitystore:GetGroupId",
      "identitystore:ListGroups",
    ]
    resources = ["*"]
  }

  statement {
    sid = "ChangeIdentityCenter"
    actions = [
      "sso:CreatePermissionSet",
      "sso:TagResource",
      "sso:AttachManagedPolicyToPermissionSet",
      "sso:ProvisionPermissionSet",
      "sso:CreateAccountAssignment",
    ]
    resources = [
      local.instance_arn,
      "arn:aws:sso:::permissionSet/${local.instance_id}/*",
      "arn:aws:sso:::account/${var.target_account_id}",
    ]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "reconciler"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

# function
resource "aws_lambda_function" "reconciler" {
  function_name    = local.function_name
  description      = "henz-iga reconciler, built from commit ${var.git_sha}"
  publish          = true # every code change becomes a numbered, immutable version
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 120
  memory_size      = 256

  environment {
    variables = {
      DRY_RUN           = var.dry_run ? "true" : "false"
      TARGET_ACCOUNT_ID = var.target_account_id
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.lambda]

  lifecycle {
    precondition {
      condition     = var.target_account_id != data.aws_caller_identity.current.account_id
      error_message = "target_account_id is the management account. Assigning there needs IAM-admin powers. Use a member account."
    }
  }
}

# Scheduled runs are not retried; the next run is the retry, and runs are safe to repeat.
resource "aws_lambda_function_event_invoke_config" "reconciler" {
  function_name          = aws_lambda_function.reconciler.function_name
  maximum_retry_attempts = 0
}

# schedule
resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${local.function_name}-schedule"
  schedule_expression = var.schedule_expression
  state               = var.schedule_enabled ? "ENABLED" : "DISABLED"
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.reconciler.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.reconciler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

# alerts
resource "aws_sns_topic" "alerts" {
  count = var.alert_email == "" ? 0 : 1
  name  = "${local.function_name}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# The function fails its invocation on any error finding, so this alarm covers both
# a bad mapping file and a failed assignment.
resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${local.function_name}-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.reconciler.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
}
