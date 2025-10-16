# AWS Config Rule
resource "aws_config_config_rule" "this" {
  name        = var.rule_name
  description = var.rule_description

  source {
    owner             = var.rule_owner
    source_identifier = var.rule_source_identifier
  }

  dynamic "scope" {
    for_each = var.resource_types != null || var.resource_id != null ? [1] : []
    content {
      compliance_resource_types = var.resource_types
      compliance_resource_id    = var.resource_id
    }
  }

  input_parameters = var.input_parameters

  depends_on = [var.config_recorder_dependency]

  tags = var.tags
}

# SSM Automation Document (optional, only if custom remediation is needed)
resource "aws_ssm_document" "remediation" {
  count = var.enable_remediation && var.ssm_document_content != null ? 1 : 0

  name            = var.ssm_document_name != null ? var.ssm_document_name : "${var.rule_name}-remediation"
  document_type   = "Automation"
  document_format = "YAML"
  content         = var.ssm_document_content

  tags = var.tags
}

# AWS Config Remediation Configuration
resource "aws_config_remediation_configuration" "this" {
  count = var.enable_remediation ? 1 : 0

  config_rule_name = aws_config_config_rule.this.name
  resource_type    = var.remediation_resource_type
  target_type      = var.remediation_target_type
  target_id        = var.remediation_target_id != null ? var.remediation_target_id : aws_ssm_document.remediation[0].name
  target_version   = var.remediation_target_version

  dynamic "parameter" {
    for_each = var.remediation_parameters
    content {
      name           = parameter.value.name
      static_value   = lookup(parameter.value, "static_value", null)
      resource_value = lookup(parameter.value, "resource_value", null)
      static_values  = lookup(parameter.value, "static_values", null)
    }
  }

  automatic                  = var.automatic_remediation
  maximum_automatic_attempts = var.max_remediation_attempts
  retry_attempt_seconds      = var.remediation_retry_seconds

  dynamic "execution_controls" {
    for_each = var.execution_controls != null ? [var.execution_controls] : []
    content {
      ssm_controls {
        concurrent_execution_rate_percentage = execution_controls.value.concurrent_execution_rate_percentage
        error_percentage                     = execution_controls.value.error_percentage
      }
    }
  }
}
