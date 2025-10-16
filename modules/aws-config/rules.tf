# AWS Config Rules (optional, controlled by variables)
# This file can be used to define Config Rules with optional remediation

# Data source to get current AWS account ID
data "aws_caller_identity" "current" {}

# Data source to get current AWS region
data "aws_region" "current" {}
