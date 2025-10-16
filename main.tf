terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

# AWS Config Setup
module "aws_config" {
  source = "./modules/aws-config"

  # Basic Config Settings
  recorder_name         = "cmmc-level2-config-recorder"
  delivery_channel_name = "cmmc-level2-config-delivery"
  config_bucket_name    = "cmmc-level2-aws-config-${data.aws_caller_identity.current.account_id}"

  # IAM Role Names
  config_role_name      = "cmmc-level2-config-role"
  remediation_role_name = "cmmc-level2-remediation-role"
  enable_remediation    = true

  # Recording Settings
  all_supported            = true
  include_global_resources = true

  # Delivery Settings
  delivery_frequency = "Six_Hours"

  tags = var.tags
}

# Create all CMMC 2.0 Level 2 Config rules
module "config_rules" {
  source   = "./modules/config-rule-remediation"
  for_each = local.cmmc_rules

  # Rule configuration
  rule_name              = each.value.name
  rule_description       = each.value.description
  rule_source_identifier = each.value.source_identifier
  resource_types         = try(each.value.resource_types, null)
  # Pass empty JSON object instead of null when no parameters (AWS Config rejects null)
  input_parameters       = lookup(each.value, "input_parameters", null) != null ? jsonencode(each.value.input_parameters) : "{}"

  # Remediation configuration
  enable_remediation        = try(each.value.enable_remediation, false)
  ssm_document_content      = try(each.value.enable_remediation, false) && lookup(each.value, "ssm_document", null) != null ? file("${path.module}/documents/${each.value.ssm_document}") : null
  remediation_resource_type = try(each.value.resource_types[0], null)
  remediation_parameters    = lookup(each.value, "remediation_parameters", [])

  # Remediation settings
  automatic_remediation     = var.enable_automatic_remediation
  max_remediation_attempts  = var.max_remediation_attempts
  remediation_retry_seconds = var.remediation_retry_seconds

  execution_controls = try(each.value.execution_controls, {
    concurrent_execution_rate_percentage = 25
    error_percentage                     = 20
  })

  # Dependencies
  config_recorder_dependency = module.aws_config.config_recorder_id

  tags = merge(var.tags, {
    CMMCLevel    = "2"
    Compliance   = "CMMC-2.0"
    Category     = each.value.category
    Remediable   = try(each.value.enable_remediation, false) ? "true" : "false"
  })
}

# Data source for current account
data "aws_caller_identity" "current" {}
