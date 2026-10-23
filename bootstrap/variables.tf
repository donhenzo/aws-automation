variable "github_repo" {
  description = "GitHub repository allowed to deploy, in owner/name form, for example myuser/henz-iga."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", var.github_repo))
    error_message = "github_repo must look like owner/name."
  }
}

variable "github_subject_repo" {
  description = "The repository exactly as it appears in the sub claim of the GitHub OIDC token. Repositories created after 15 July 2026 use the immutable form owner@OWNERID/repo@REPOID. Leave empty to use github_repo (the older name-only form)."
  type        = string
  default     = ""

  validation {
    condition     = var.github_subject_repo == "" || can(regex("^[A-Za-z0-9-]+(@[0-9]+)?/[A-Za-z0-9._-]+(@[0-9]+)?$", var.github_subject_repo))
    error_message = "github_subject_repo must look like owner@123/repo@456 (or owner/repo)."
  }
}

variable "state_bucket" {
  description = "Name of the S3 bucket that holds the Terraform state."
  type        = string
}

variable "region" {
  type    = string
  default = "eu-north-1"
}

variable "name_prefix" {
  description = "Prefix of the resources the pipeline may manage. The pipeline roles themselves use a different prefix so the pipeline cannot edit itself."
  type        = string
  default     = "henz-iga"
}
