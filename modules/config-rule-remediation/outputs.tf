output "config_rule_id" {
  description = "ID of the AWS Config rule"
  value       = aws_config_config_rule.this.id
}

output "config_rule_arn" {
  description = "ARN of the AWS Config rule"
  value       = aws_config_config_rule.this.arn
}

output "config_rule_name" {
  description = "Name of the AWS Config rule"
  value       = aws_config_config_rule.this.name
}

output "ssm_document_name" {
  description = "Name of the SSM automation document (if created)"
  value       = var.enable_remediation && var.ssm_document_content != null ? aws_ssm_document.remediation[0].name : null
}

output "ssm_document_arn" {
  description = "ARN of the SSM automation document (if created)"
  value       = var.enable_remediation && var.ssm_document_content != null ? aws_ssm_document.remediation[0].arn : null
}

output "remediation_configuration_arn" {
  description = "ARN of the remediation configuration (if enabled)"
  value       = var.enable_remediation ? aws_config_remediation_configuration.this[0].arn : null
}
