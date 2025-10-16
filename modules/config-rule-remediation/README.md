# AWS Config Rule with Remediation Module

A reusable Terraform module for creating AWS Config rules with optional automated remediation using SSM Automation documents.

## Features

- Create AWS Config rules (managed or custom)
- Optional SSM automation document creation
- Automated remediation configuration
- Flexible parameter configuration
- Execution controls for remediation
- Full support for AWS managed Config rules

## Usage

### Basic Config Rule (No Remediation)

```hcl
module "s3_public_write_check" {
  source = "./modules/config-rule-remediation"

  rule_name              = "s3-bucket-public-write-prohibited"
  rule_source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  resource_types         = ["AWS::S3::Bucket"]

  enable_remediation = false
}
```

### Config Rule with Remediation

```hcl
module "s3_encryption_rule" {
  source = "./modules/config-rule-remediation"

  # Rule configuration
  rule_name              = "s3-bucket-encryption-enabled"
  rule_description       = "Ensures S3 buckets have encryption enabled"
  rule_source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  resource_types         = ["AWS::S3::Bucket"]

  # Remediation configuration
  enable_remediation        = true
  ssm_document_content      = file("${path.module}/documents/s3-encryption.yaml")
  remediation_resource_type = "AWS::S3::Bucket"

  remediation_parameters = [
    {
      name         = "AutomationAssumeRole"
      static_value = "arn:aws:iam::123456789012:role/ConfigRemediationRole"
    },
    {
      name           = "BucketName"
      resource_value = "RESOURCE_ID"
    }
  ]

  # Remediation settings
  automatic_remediation     = true
  max_remediation_attempts  = 5
  remediation_retry_seconds = 60

  execution_controls = {
    concurrent_execution_rate_percentage = 25
    error_percentage                     = 20
  }
}
```

### Using Existing SSM Document

```hcl
module "rule_with_existing_document" {
  source = "./modules/config-rule-remediation"

  rule_name              = "my-config-rule"
  rule_source_identifier = "MY_RULE_IDENTIFIER"

  enable_remediation   = true
  remediation_target_id = "AWS-PublishSNSNotification"  # Existing AWS document

  remediation_parameters = [
    {
      name         = "TopicArn"
      static_value = "arn:aws:sns:us-east-1:123456789012:my-topic"
    }
  ]
}
```

### For_each Pattern

```hcl
locals {
  config_rules = {
    encryption = { ... }
    versioning = { ... }
  }
}

module "config_rules" {
  source   = "./modules/config-rule-remediation"
  for_each = local.config_rules

  rule_name              = each.value.name
  rule_source_identifier = each.value.source_identifier
  ...
}
```

## Inputs

### Required Inputs

| Name | Type | Description |
|------|------|-------------|
| `rule_name` | string | Name of the AWS Config rule |
| `rule_source_identifier` | string | Source identifier for the Config rule (e.g., S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED) |

### Optional Rule Inputs

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `rule_description` | string | null | Description of the Config rule |
| `rule_owner` | string | "AWS" | Owner of the Config rule (AWS or CUSTOM_LAMBDA) |
| `resource_types` | list(string) | null | Resource types to evaluate |
| `resource_id` | string | null | Specific resource ID to evaluate |
| `input_parameters` | string | null | Input parameters in JSON format |
| `config_recorder_dependency` | any | null | Dependency on Config recorder |

### Optional Remediation Inputs

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `enable_remediation` | bool | false | Enable automated remediation |
| `ssm_document_name` | string | null | Name for SSM document (defaults to {rule_name}-remediation) |
| `ssm_document_content` | string | null | YAML content of SSM automation document |
| `remediation_resource_type` | string | null | Resource type for remediation (e.g., AWS::S3::Bucket) |
| `remediation_target_type` | string | "SSM_DOCUMENT" | Type of remediation target |
| `remediation_target_id` | string | null | ID of remediation target (uses created SSM doc if not provided) |
| `remediation_target_version` | string | "1" | Version of remediation target |
| `remediation_parameters` | list(object) | [] | Parameters for remediation action |
| `automatic_remediation` | bool | true | Enable automatic remediation execution |
| `max_remediation_attempts` | number | 5 | Maximum number of remediation attempts |
| `remediation_retry_seconds` | number | 60 | Time between remediation attempts |
| `execution_controls` | object | null | Execution controls for remediation |

### Remediation Parameters Object

```hcl
remediation_parameters = [
  {
    name           = "ParameterName"
    static_value   = "static-value"      # Use for fixed values
    resource_value = "RESOURCE_ID"       # Use for resource-specific values
    static_values  = ["val1", "val2"]    # Use for list values
  }
]
```

### Execution Controls Object

```hcl
execution_controls = {
  concurrent_execution_rate_percentage = 25  # Max % of resources to remediate at once
  error_percentage                     = 20  # Stop if this % of remediations fail
}
```

## Outputs

| Name | Description |
|------|-------------|
| `config_rule_id` | ID of the AWS Config rule |
| `config_rule_arn` | ARN of the AWS Config rule |
| `config_rule_name` | Name of the AWS Config rule |
| `ssm_document_name` | Name of the SSM automation document (if created) |
| `ssm_document_arn` | ARN of the SSM automation document (if created) |
| `remediation_configuration_arn` | ARN of the remediation configuration (if enabled) |

## SSM Automation Document Format

SSM documents should follow this structure:

```yaml
schemaVersion: '0.3'
description: Description of what this remediation does
assumeRole: '{{ AutomationAssumeRole }}'
parameters:
  ResourceId:
    type: String
    description: ID of the resource to remediate
  AutomationAssumeRole:
    type: String
    description: IAM role for automation execution
mainSteps:
  - name: RemediationStep
    action: 'aws:executeAwsApi'
    inputs:
      Service: service-name
      Api: ApiName
      Parameter: '{{ ResourceId }}'
    description: Step description
    isEnd: true
```

## Common AWS Managed Config Rules

| Rule Identifier | Description | Resource Type |
|----------------|-------------|---------------|
| S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED | S3 bucket encryption | AWS::S3::Bucket |
| S3_BUCKET_VERSIONING_ENABLED | S3 bucket versioning | AWS::S3::Bucket |
| S3_BUCKET_PUBLIC_READ_PROHIBITED | S3 public read access | AWS::S3::Bucket |
| S3_BUCKET_PUBLIC_WRITE_PROHIBITED | S3 public write access | AWS::S3::Bucket |
| EC2_EBS_ENCRYPTION_BY_DEFAULT | EBS encryption enabled | Account setting |
| RDS_STORAGE_ENCRYPTED | RDS encryption | AWS::RDS::DBInstance |
| CLOUDTRAIL_ENABLED | CloudTrail enabled | Account setting |
| IAM_PASSWORD_POLICY | IAM password policy | Account setting |

Full list: https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html

## Requirements

- Terraform >= 1.0
- AWS Provider >= 5.0
- AWS Config must be enabled in the account/region
- IAM role for remediation (if using remediation)

## Examples

See the examples directory:
- `examples/s3-encryption-remediation/` - Single rule example
- `examples/multiple-rules-foreach/` - Multiple rules with for_each
- `examples/multiple-rules-modules/` - Multiple rules with module calls

## Limitations

- SSM automation documents are limited to 64 KB
- Config rules are region-specific (deploy in each region)
- Some AWS managed rules require specific input parameters
- Remediation cannot be applied to all rule types (e.g., account-level settings)

## License

MIT License
