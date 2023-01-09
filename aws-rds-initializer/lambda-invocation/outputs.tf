output "result" {
  description = "String result of Lambda execution"
  value       = data.aws_lambda_invocation.lambda_invoke.result
}