variable "region" {
  description = "Home region of the IAM Identity Center instance."
  type        = string
  default     = "eu-north-1"
}

variable "target_account_id" {
  description = "12-digit ID of the MEMBER account that permission sets are assigned on. Not the management account: assigning there needs IAM-admin powers."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.target_account_id))
    error_message = "target_account_id must be a 12-digit AWS account ID."
  }
}

variable "dry_run" {
  description = "true = the reconciler only reports what it would do. Set to false to make real changes."
  type        = bool
  default     = true
}

variable "schedule_enabled" {
  description = "false = the timer exists but is switched off, so you invoke the function by hand while testing."
  type        = bool
  default     = false
}

variable "schedule_expression" {
  description = "How often the reconciler runs when the schedule is enabled."
  type        = string
  default     = "rate(5 minutes)"
}

variable "alert_email" {
  description = "Optional. If set, failures are emailed here (you must confirm the subscription)."
  type        = string
  default     = ""
}

variable "git_sha" {
  description = "Commit that this deployment was built from. Set by the pipeline; recorded on the function."
  type        = string
  default     = "local"
}
