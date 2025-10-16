# CMMC 2.0 Level 2 Config Rules
# Rules are defined in terraform.tfvars or rules.auto.tfvars
# This file builds the local.cmmc_rules from var.config_rules and injects computed values

locals {
  # Build cmmc_rules from variable, injecting computed values and handling variable substitutions
  cmmc_rules = {
    for key, rule in var.config_rules : key => merge(
      rule,
      # Only include input_parameters if the rule has them (to avoid passing null to AWS API)
      rule.input_parameters != null ? {
        input_parameters = {
          for param_key, param_value in rule.input_parameters :
          param_key => (
            param_value == "{{max_access_key_age}}" ? tostring(var.max_access_key_age) :
            param_value == "{{log_retention_days}}" ? tostring(var.log_retention_days) :
            param_value == "{{certificate_expiration_days}}" ? tostring(var.certificate_expiration_days) :
            param_value
          )
        }
      } : {},
      {
        # Handle conditional remediation based on required variables
        enable_remediation = (
          # S3 logging requires s3_logging_bucket variable
          key == "s3_bucket_logging_enabled" && var.s3_logging_bucket == "" ? false :
          # CloudTrail encryption requires cloudtrail_kms_key_id variable
          key == "cloud_trail_encryption_enabled" && var.cloudtrail_kms_key_id == "" ? false :
          # Default to rule's enable_remediation value
          rule.enable_remediation
        )

        # Inject computed values into remediation_parameters
        remediation_parameters = rule.enable_remediation && rule.remediation_parameters != null ? concat(
          [
            {
              name         = "AutomationAssumeRole"
              static_value = module.aws_config.remediation_role_arn
            }
          ],
          [
            for param in rule.remediation_parameters : merge(param, {
              # Substitute variable placeholders with actual values
              static_value = param.static_value != null ? (
                param.static_value == "{{s3_logging_bucket}}" ? var.s3_logging_bucket :
                param.static_value == "{{cloudtrail_kms_key_id}}" ? var.cloudtrail_kms_key_id :
                param.static_value == "{{log_retention_days}}" ? tostring(var.log_retention_days) :
                param.static_value
              ) : null
            })
          ]
        ) : []
      }
    )
  }
}
