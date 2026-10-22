output "plan_role_arn" {
  description = "Put this in the GitHub repository variable AWS_PLAN_ROLE_ARN."
  value       = aws_iam_role.plan.arn
}

output "apply_role_arn" {
  description = "Put this in the GitHub repository variable AWS_APPLY_ROLE_ARN."
  value       = aws_iam_role.apply.arn
}
