# AWS Config Outputs
output "config_recorder_id" {
  description = "ID of the AWS Config Recorder"
  value       = module.aws_config.config_recorder_id
}

output "config_bucket_name" {
  description = "Name of the S3 bucket for Config snapshots"
  value       = module.aws_config.config_bucket_name
}

output "config_role_arn" {
  description = "ARN of the IAM role for AWS Config"
  value       = module.aws_config.config_role_arn
}

output "remediation_role_arn" {
  description = "ARN of the IAM role for Config remediation"
  value       = module.aws_config.remediation_role_arn
}

# Config Rules Outputs
output "total_rules_deployed" {
  description = "Total number of Config rules deployed"
  value       = length(module.config_rules)
}

output "rules_with_remediation" {
  description = "List of Config rules with automatic remediation enabled"
  value = [
    for key, rule in local.cmmc_rules :
    rule.name
    if try(rule.enable_remediation, false)
  ]
}

output "rules_by_category" {
  description = "Count of rules by category"
  value = {
    for category in distinct([for rule in local.cmmc_rules : rule.category]) :
    category => length([for rule in local.cmmc_rules : rule if rule.category == category])
  }
}

output "config_rule_arns" {
  description = "ARNs of all deployed Config rules"
  value = {
    for key, rule in module.config_rules :
    key => rule.config_rule_arn
  }
}

output "remediation_enabled_by_category" {
  description = "Count of rules with remediation enabled by category"
  value = {
    for category in distinct([for rule in local.cmmc_rules : rule.category]) :
    category => length([
      for rule in local.cmmc_rules :
      rule if rule.category == category && try(rule.enable_remediation, false)
    ])
  }
}

# Summary Statistics
output "compliance_summary" {
  description = "Summary of CMMC 2.0 Level 2 compliance coverage"
  value = {
    total_rules                = length(local.cmmc_rules)
    rules_with_remediation     = length([for rule in local.cmmc_rules : rule if try(rule.enable_remediation, false)])
    rules_detection_only       = length([for rule in local.cmmc_rules : rule if !try(rule.enable_remediation, false)])
    remediation_enabled        = var.enable_automatic_remediation
    categories_covered         = length(distinct([for rule in local.cmmc_rules : rule.category]))
    automatic_remediation_rate = format("%.1f%%", (length([for rule in local.cmmc_rules : rule if try(rule.enable_remediation, false)]) / length(local.cmmc_rules)) * 100)
  }
}

# High-Priority Remediable Rules
output "high_priority_remediations" {
  description = "High-priority rules with automatic remediation available"
  value = [
    for key, rule in local.cmmc_rules :
    {
      name     = rule.name
      category = rule.category
      description = rule.description
    }
    if try(rule.enable_remediation, false) && contains(
      ["S3", "RDS", "CloudTrail", "KMS", "VPC"],
      rule.category
    )
  ]
}
