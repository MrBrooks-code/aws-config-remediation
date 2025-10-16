# Config Rule Variables
variable "rule_name" {
  description = "Name of the AWS Config rule"
  type        = string
}

variable "rule_description" {
  description = "Description of the AWS Config rule"
  type        = string
  default     = null
}

variable "rule_owner" {
  description = "Owner of the Config rule (AWS or CUSTOM_LAMBDA)"
  type        = string
  default     = "AWS"
}

variable "rule_source_identifier" {
  description = "Source identifier for the Config rule (e.g., S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED)"
  type        = string
}

variable "resource_types" {
  description = "List of resource types to evaluate (e.g., ['AWS::S3::Bucket'])"
  type        = list(string)
  default     = null
}

variable "resource_id" {
  description = "Specific resource ID to evaluate"
  type        = string
  default     = null
}

variable "input_parameters" {
  description = "Input parameters for the Config rule in JSON format"
  type        = string
  default     = null
}

variable "config_recorder_dependency" {
  description = "Dependency on Config recorder to ensure proper ordering"
  type        = any
  default     = null
}

# Remediation Variables
variable "enable_remediation" {
  description = "Enable automatic remediation for this rule"
  type        = bool
  default     = false
}

variable "ssm_document_name" {
  description = "Name for the SSM automation document (defaults to rule_name-remediation)"
  type        = string
  default     = null
}

variable "ssm_document_content" {
  description = "Content of the SSM automation document in YAML format"
  type        = string
  default     = null
}

variable "remediation_resource_type" {
  description = "Resource type for remediation (e.g., AWS::S3::Bucket)"
  type        = string
  default     = null
}

variable "remediation_target_type" {
  description = "Type of remediation target (SSM_DOCUMENT)"
  type        = string
  default     = "SSM_DOCUMENT"
}

variable "remediation_target_id" {
  description = "ID of the remediation target (SSM document name or ARN). If not provided, uses the created SSM document"
  type        = string
  default     = null
}

variable "remediation_target_version" {
  description = "Version of the remediation target"
  type        = string
  default     = "1"
}

variable "remediation_parameters" {
  description = "Parameters for the remediation action"
  type = list(object({
    name           = string
    static_value   = optional(string)
    resource_value = optional(string)
    static_values  = optional(list(string))
  }))
  default = []
}

variable "automatic_remediation" {
  description = "Enable automatic remediation execution"
  type        = bool
  default     = true
}

variable "max_remediation_attempts" {
  description = "Maximum number of automatic remediation attempts"
  type        = number
  default     = 5
}

variable "remediation_retry_seconds" {
  description = "Time in seconds between remediation attempts"
  type        = number
  default     = 60
}

variable "execution_controls" {
  description = "Execution controls for remediation"
  type = object({
    concurrent_execution_rate_percentage = number
    error_percentage                     = number
  })
  default = null
}

# Common Variables
variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
