output "config_recorder_id" {
  description = "ID of the AWS Config Recorder"
  value       = aws_config_configuration_recorder.main.id
}

output "config_delivery_channel_id" {
  description = "ID of the AWS Config Delivery Channel"
  value       = aws_config_delivery_channel.main.id
}

output "config_bucket_name" {
  description = "Name of the S3 bucket for Config snapshots"
  value       = aws_s3_bucket.config.id
}

output "config_bucket_arn" {
  description = "ARN of the S3 bucket for Config snapshots"
  value       = aws_s3_bucket.config.arn
}

output "config_role_arn" {
  description = "ARN of the IAM role for AWS Config (Service-Linked Role)"
  value       = data.aws_iam_role.config.arn
}

output "config_role_name" {
  description = "Name of the IAM role for AWS Config (Service-Linked Role)"
  value       = data.aws_iam_role.config.name
}

output "remediation_role_arn" {
  description = "ARN of the IAM role for Config remediation"
  value       = var.enable_remediation ? aws_iam_role.remediation[0].arn : null
}

output "remediation_role_name" {
  description = "Name of the IAM role for Config remediation"
  value       = var.enable_remediation ? aws_iam_role.remediation[0].name : null
}
