# AWS Config Service-Linked Role
# Use the existing service-linked role managed by AWS
# This role is automatically created when you first use AWS Config
data "aws_iam_role" "config" {
  name = "AWSServiceRoleForConfig"
}

# IAM Role for Config Remediation (SSM Automation)
resource "aws_iam_role" "remediation" {
  count              = var.enable_remediation ? 1 : 0
  name               = var.remediation_role_name
  assume_role_policy = data.aws_iam_policy_document.remediation_assume_role[0].json

  tags = var.tags
}

# Assume Role Policy for SSM Automation and Config
data "aws_iam_policy_document" "remediation_assume_role" {
  count = var.enable_remediation ? 1 : 0

  statement {
    effect = "Allow"

    principals {
      type = "Service"
      identifiers = [
        "ssm.amazonaws.com",
        "config.amazonaws.com"
      ]
    }

    actions = ["sts:AssumeRole"]
  }
}

# Policy for Remediation Role (customize based on your needs)
resource "aws_iam_role_policy" "remediation_policy" {
  count  = var.enable_remediation ? 1 : 0
  name   = "${var.remediation_role_name}-policy"
  role   = aws_iam_role.remediation[0].id
  policy = data.aws_iam_policy_document.remediation_policy[0].json
}

data "aws_iam_policy_document" "remediation_policy" {
  count = var.enable_remediation ? 1 : 0

  statement {
    sid    = "RemediationActions"
    effect = "Allow"

    actions = [
      # S3 Operations
      "s3:PutEncryptionConfiguration",
      "s3:GetEncryptionConfiguration",
      "s3:PutBucketEncryption",
      "s3:PutBucketVersioning",
      "s3:GetBucketVersioning",
      "s3:PutBucketPublicAccessBlock",
      "s3:GetBucketPublicAccessBlock",
      "s3:PutAccountPublicAccessBlock",
      "s3:GetAccountPublicAccessBlock",
      "s3:PutBucketLogging",
      "s3:GetBucketLogging",
      "s3:PutBucketPolicy",
      "s3:GetBucketPolicy",
      # RDS Operations
      "rds:ModifyDBInstance",
      "rds:ModifyDBSnapshot",
      "rds:ModifyDBSnapshotAttribute",
      "rds:DescribeDBInstances",
      "rds:DescribeDBSnapshots",
      # CloudTrail Operations
      "cloudtrail:UpdateTrail",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      # CloudWatch Logs Operations
      "logs:PutRetentionPolicy",
      "logs:DescribeLogGroups",
      # KMS Operations
      "kms:EnableKeyRotation",
      "kms:GetKeyRotationStatus",
      "kms:DescribeKey",
      # EC2 Operations
      "ec2:EnableEbsEncryptionByDefault",
      "ec2:GetEbsEncryptionByDefault",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupRules",
      # Config Operations
      "config:ListDiscoveredResources",
      "config:GetResourceConfigHistory",
      # SSM Operations
      "ssm:StartAutomationExecution",
      "ssm:GetAutomationExecution",
      "ssm:DescribeAutomationExecutions"
    ]

    resources = ["*"]
  }

  statement {
    sid    = "PassRoleToSSM"
    effect = "Allow"

    actions = [
      "iam:PassRole"
    ]

    resources = [aws_iam_role.remediation[0].arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ssm.amazonaws.com"]
    }
  }
}
