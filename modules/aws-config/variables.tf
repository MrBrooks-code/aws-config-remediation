variable "recorder_name" {
  description = "Name of the AWS Config Recorder"
  type        = string
  default     = "aws-config-recorder"
}

variable "delivery_channel_name" {
  description = "Name of the AWS Config Delivery Channel"
  type        = string
  default     = "aws-config-delivery-channel"
}

variable "config_bucket_name" {
  description = "Name of the S3 bucket for AWS Config snapshots"
  type        = string
}

variable "config_role_name" {
  description = "DEPRECATED: AWS Config now uses the service-linked role AWSServiceRoleForConfig"
  type        = string
  default     = "aws-config-role"
}

variable "remediation_role_name" {
  description = "Name of the IAM role for Config remediation"
  type        = string
  default     = "aws-config-remediation-role"
}

variable "enable_remediation" {
  description = "Enable remediation IAM role creation"
  type        = bool
  default     = false
}

variable "s3_key_prefix" {
  description = "Prefix for the S3 bucket key for Config snapshots"
  type        = string
  default     = "config"
}

variable "delivery_frequency" {
  description = "Frequency of Config snapshot delivery to S3"
  type        = string
  default     = "TwentyFour_Hours"

  validation {
    condition = contains([
      "One_Hour",
      "Three_Hours",
      "Six_Hours",
      "Twelve_Hours",
      "TwentyFour_Hours"
    ], var.delivery_frequency)
    error_message = "Delivery frequency must be one of: One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours"
  }
}

variable "enable_recorder" {
  description = "Enable the Config Recorder"
  type        = bool
  default     = true
}

variable "all_supported" {
  description = "Record all supported resource types"
  type        = bool
  default     = true
}

variable "include_global_resources" {
  description = "Include global resources like IAM"
  type        = bool
  default     = true
}

variable "resource_types" {
  description = "List of resource types to record (only used if all_supported is false)"
  type        = list(string)
  default     = []
}

variable "force_destroy_bucket" {
  description = "Allow deletion of non-empty S3 bucket"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
