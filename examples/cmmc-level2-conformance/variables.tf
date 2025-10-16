variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile to use for authentication"
  type        = string
  default     = "cc"
}

# IAM Policy Parameters
variable "max_access_key_age" {
  description = "Maximum age in days for access keys"
  type        = number
  default     = 90
}

# CloudTrail & Logging Parameters
variable "log_retention_days" {
  description = "CloudWatch log group retention period in days"
  type        = number
  default     = 365
}

variable "cloudtrail_kms_key_id" {
  description = "KMS key ID for CloudTrail encryption (leave empty to skip encryption remediation)"
  type        = string
  default     = ""
}

# S3 Parameters
variable "s3_logging_bucket" {
  description = "S3 bucket for storing access logs"
  type        = string
  default     = ""
}

# Network Parameters
variable "authorized_vpc_ids" {
  description = "Comma-separated list of authorized VPC IDs for internet gateways"
  type        = string
  default     = ""
}

# Certificate Parameters
variable "certificate_expiration_days" {
  description = "Days before certificate expiration to trigger alerts"
  type        = number
  default     = 30
}

# Remediation Settings
variable "enable_automatic_remediation" {
  description = "Enable automatic remediation for non-compliant resources"
  type        = bool
  default     = false # Set to false by default for safety
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

# Tags
variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Environment  = "compliance"
    Framework    = "CMMC-2.0"
    Level        = "2"
    ManagedBy    = "Terraform"
    CostCenter   = "Security"
  }
}

# Config Rules
variable "config_rules" {
  description = "Map of AWS Config rules to deploy with their configurations"
  type = map(object({
    category           = string
    name               = string
    description        = string
    source_identifier  = string
    resource_types     = optional(list(string))
    input_parameters   = optional(map(string))
    enable_remediation = optional(bool, false)
    ssm_document       = optional(string)
    remediation_parameters = optional(list(object({
      name           = string
      static_value   = optional(string)
      resource_value = optional(string)
    })))
  }))
  default = {}
}
