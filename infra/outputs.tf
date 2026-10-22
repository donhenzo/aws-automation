output "function_name" {
  value = aws_lambda_function.reconciler.function_name
}

output "log_group" {
  value = aws_cloudwatch_log_group.lambda.name
}

output "identity_center_instance_arn" {
  value = local.instance_arn
}
