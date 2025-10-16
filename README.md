# AWS Config - CMMC 2.0 Level 2 Conformance Pack

This Terraform example deploys a complete AWS Config rules pack for **CMMC (Cybersecurity Maturity Model Certification) 2.0 Level 2** compliance, including automated remediation for applicable rules using SSM documents.

## Overview

CMMC 2.0 Level 2 requires organizations to implement good cybersecurity hygiene practices. This conformance pack implements **127 AWS Config rules** across multiple service categories to help organizations achieve and maintain CMMC Level 2 compliance.

**Note:** 7 additional rules are commented out in `rules.tf` because they require customer-specific configuration (approved AMI IDs, instance types, CloudWatch alarm parameters, etc.). You can uncomment and configure these rules based on your requirements.

### What This Example Provides

- **127 Active Config Rules** organized by service category (7 more available but commented out)
- **15+ Automated Remediations** using AWS Systems Manager (SSM) Automation Documents
- **Continuous Compliance Monitoring** via AWS Config
- **Customizable Parameters** for security thresholds
- **Detailed Compliance Reporting** via Terraform outputs

## Rules Summary

### Total Rules by Category

| Category | Total Rules | Rules with Remediation | Detection Only | Commented Out |
|----------|-------------|------------------------|----------------|---------------|
| IAM | 16 | 0 | 16 | 0 |
| S3 | 10 | 6 | 4 | 0 |
| EC2 | 15 | 2 | 13 | 2 |
| RDS | 10 | 4 | 6 | 0 |
| CloudTrail | 7 | 3 | 4 | 0 |
| KMS | 8 | 1 | 7 | 0 |
| VPC | 6 | 1 | 5 | 1 |
| ELB | 8 | 0 | 8 | 0 |
| Backup | 5 | 0 | 5 | 0 |
| Lambda | 4 | 0 | 4 | 1 |
| API Gateway | 5 | 0 | 5 | 0 |
| CloudWatch | 0 | 0 | 0 | 3 |
| Other Services | 33 | 0 | 33 | 0 |
| **TOTAL** | **127** | **17** | **110** | **7** |

### Commented Out Rules (Require Customer Configuration)

The following 7 rules are commented out in `rules.tf` and can be enabled by providing the required parameters:

1. **lambda-function-settings-check** - Requires allowed runtime versions (e.g., `python3.11,nodejs20.x`)
2. **cloudwatch-alarm-action-check** - Requires alarm action settings
3. **cloudwatch-alarm-resource-check** - Requires resource type and metric name
4. **cloudwatch-alarm-settings-check** - Requires metric name
5. **internet-gateway-authorized-vpc-only** - Requires authorized VPC IDs
6. **desired-instance-type** - Requires approved EC2 instance types
7. **approved-amis-by-id** - Requires approved AMI IDs

### Automated Remediations

The following rules include automated remediation capabilities:

**Note:** Two remediations require optional variables to be configured:
- **s3-bucket-logging-enabled**: Requires `s3_logging_bucket` variable
- **cloud-trail-encryption-enabled**: Requires `cloudtrail_kms_key_id` variable

These remediations will be automatically disabled if the required variables are not set.

#### S3 (6 rules)
- `s3-bucket-public-read-prohibited` - Block public read access
- `s3-bucket-public-write-prohibited` - Block public write access
- `s3-bucket-server-side-encryption-enabled` - Enable encryption
- `s3-bucket-versioning-enabled` - Enable versioning
- `s3-bucket-logging-enabled` - Enable access logging *(requires `s3_logging_bucket` variable)*
- `s3-bucket-ssl-requests-only` - Enforce SSL-only access

#### RDS (4 rules)
- `rds-automatic-minor-version-upgrade-enabled` - Enable minor version upgrades
- `db-instance-backup-enabled` - Enable automated backups
- `rds-instance-deletion-protection-enabled` - Enable deletion protection
- `rds-snapshots-public-prohibited` - Make public snapshots private

#### CloudTrail (3 rules)
- `cloud-trail-encryption-enabled` - Enable CloudTrail encryption *(requires `cloudtrail_kms_key_id` variable)*
- `cloud-trail-log-file-validation-enabled` - Enable log validation
- `cw-loggroup-retention-period-check` - Set CloudWatch log retention

#### KMS (1 rule)
- `cmk-backing-key-rotation-enabled` - Enable key rotation

#### EC2 (1 rule)
- `ec2-ebs-encryption-by-default` - Enable EBS encryption by default

#### VPC (1 rule)
- `restricted-ssh` - Remove unrestricted SSH access (0.0.0.0/0)

## Prerequisites

1. **Terraform** >= 1.0
2. **AWS Provider** ~> 5.0
3. **AWS CLI** configured with appropriate credentials
4. **IAM Permissions** to create:
   - AWS Config resources (recorder, delivery channel, rules)
   - S3 buckets and policies
   - IAM roles and policies
   - SSM Automation documents
   - Config remediation configurations

## Configuration Parameters

### Basic Settings

```hcl
aws_region  = "us-east-1"
aws_profile = "cc"
```

### Security Parameters

| Variable | Description | Default |
|----------|-------------|---------|
| `max_access_key_age` | Maximum age for IAM access keys (days) | 90 |
| `log_retention_days` | CloudWatch log retention (days) | 365 |
| `cloudtrail_kms_key_id` | KMS key for CloudTrail encryption | "" (empty) |
| `certificate_expiration_days` | ACM certificate expiration warning threshold | 30 |

### Remediation Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `enable_automatic_remediation` | Enable automatic remediation | `false` |
| `max_remediation_attempts` | Maximum remediation retry attempts | 5 |
| `remediation_retry_seconds` | Seconds between retry attempts | 60 |

**IMPORTANT:** `enable_automatic_remediation` is set to `false` by default for safety. When enabled, AWS Config will automatically remediate non-compliant resources without manual intervention.

### Optional Parameters

| Variable | Description | Required for | Default |
|----------|-------------|--------------|---------|
| `s3_logging_bucket` | S3 bucket for access logs | S3 logging remediation | `""` (disabled) |
| `cloudtrail_kms_key_id` | KMS key ARN | CloudTrail encryption remediation | `""` (disabled) |
| `authorized_vpc_ids` | Comma-separated VPC IDs | Internet gateway rule (commented out) | `""` |

**Important**: Rules requiring these variables will deploy and detect non-compliance, but automatic remediation will only be enabled when you provide the required values.

## Deployment Instructions

### 1. Clone the Repository

```bash
git clone <repository-url>
cd examples/cmmc-level2-conformance
```

### 2. Create terraform.tfvars

```hcl
# Required
aws_region  = "us-east-1"
aws_profile = "cc"

# Optional - Customize security thresholds
max_access_key_age          = 90
log_retention_days          = 365
certificate_expiration_days = 30

# Optional - Required for specific remediations
s3_logging_bucket    = "my-logging-bucket-name"
cloudtrail_kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"

# Remediation settings (start with automatic remediation disabled)
enable_automatic_remediation = false
max_remediation_attempts     = 5
remediation_retry_seconds    = 60
```

### 3. Initialize Terraform

```bash
terraform init
```

### 4. Review the Plan

```bash
terraform plan
```

### 5. Deploy

```bash
terraform apply
```

### 6. Enable Automatic Remediation (Optional)

After validating the deployment:

```hcl
# In terraform.tfvars
enable_automatic_remediation = true
```

```bash
terraform apply
```

## Post-Deployment

### Verify Deployment

1. Check AWS Config Console:
   - Navigate to AWS Config > Rules
   - Verify all 134 rules are deployed and evaluating

2. Review Terraform outputs:
```bash
terraform output compliance_summary
terraform output rules_by_category
terraform output rules_with_remediation
```

### Monitor Compliance

```bash
# View compliance summary
terraform output compliance_summary

# View rules with remediation
terraform output rules_with_remediation

# View high-priority remediations
terraform output high_priority_remediations
```

## Testing Remediation

### Manual Testing (Safe)

1. With `enable_automatic_remediation = false`:
   - Deploy the infrastructure
   - Create a non-compliant resource (e.g., unencrypted S3 bucket)
   - Wait for Config to detect non-compliance
   - Manually trigger remediation from AWS Config Console
   - Verify resource is remediated

### Automatic Remediation (Production)

1. Set `enable_automatic_remediation = true`
2. Create a non-compliant resource
3. Config will automatically remediate within retry parameters
4. Monitor remediation actions in:
   - AWS Config Console > Remediation actions
   - Systems Manager > Automation executions


## Customization

### Enabling Commented-Out Rules

To enable rules that require customer-specific configuration, edit `rules.tf` and uncomment the desired rule, then provide the required parameters:

```hcl
# Example: Enable Lambda runtime check
lambda_function_settings_check = {
  category           = "Lambda"
  name               = "lambda-function-settings-check"
  description        = "Checks that Lambda functions are properly configured"
  source_identifier  = "LAMBDA_FUNCTION_SETTINGS_CHECK"
  resource_types     = ["AWS::Lambda::Function"]
  input_parameters   = { runtime = "python3.11,nodejs20.x,java17" }  # Your allowed runtimes
  enable_remediation = false
}
```

Then run `terraform apply` to deploy the new rule.

### Disabling Specific Rules

Edit `rules.tf` and comment out unwanted rules:

```hcl
# Disable a specific rule
# iam_password_policy = {
#   category          = "IAM"
#   name              = "iam-password-policy"
#   ...
# }
```

### Modifying Remediation Parameters

Edit the `remediation_parameters` in `rules.tf`:

```hcl
s3_bucket_logging_enabled = {
  remediation_parameters = [
    { name = "AutomationAssumeRole", static_value = module.aws_config.remediation_role_arn },
    { name = "BucketName", resource_value = "RESOURCE_ID" },
    { name = "TargetBucket", static_value = "your-custom-logging-bucket" }
  ]
}
```

### Adding Custom Remediation Documents

1. Create a new SSM document in `documents/<service>/`:
```yaml
schemaVersion: '0.3'
description: Your custom remediation
assumeRole: '{{ AutomationAssumeRole }}'
parameters:
  # Your parameters
mainSteps:
  # Your remediation steps
```

2. Reference it in `rules.tf`:
```hcl
your_rule = {
  enable_remediation = true
  ssm_document      = "service/your-document.yaml"
  remediation_parameters = [...]
}
```

## Compliance Mapping

This conformance pack addresses CMMC 2.0 Level 2 requirements including:

- **Access Control (AC)**: IAM, VPC, Security Group rules
- **Audit and Accountability (AU)**: CloudTrail, CloudWatch Logs rules
- **System and Communications Protection (SC)**: Encryption, SSL/TLS rules
- **System and Information Integrity (SI)**: Monitoring, logging rules
- **Incident Response (IR)**: Automated remediation capabilities
- **Risk Assessment (RA)**: Continuous compliance monitoring

## Troubleshooting

### Rules Not Evaluating

1. Check Config Recorder status:
```bash
aws configservice describe-configuration-recorder-status
```

2. Verify IAM permissions for Config service role

### Remediation Failures

1. Check Systems Manager Automation executions:
```bash
aws ssm describe-automation-executions --filters Key=ExecutionStatus,Values=Failed
```

2. Review IAM permissions for remediation role
3. Check CloudWatch Logs for SSM execution details

### Common Issues

| Issue | Solution |
|-------|----------|
| "Config recorder already exists" | Import existing recorder or delete it |
| "S3 bucket already exists" | Use unique bucket name with account ID |
| "Insufficient permissions" | Review IAM policies in `modules/aws-config/iam.tf` |
| "Remediation not triggering" | Ensure `enable_automatic_remediation = true` |

## Security Considerations

### Least Privilege

- IAM roles are scoped to minimum required permissions
- Remediation actions are logged in CloudTrail
- S3 buckets use encryption and versioning

### Automatic Remediation Risks

Before enabling automatic remediation:

1. **Test in non-production** environment first
2. **Review** each remediation action in `documents/`
3. **Understand** that resources will be automatically modified
4. **Monitor** initial remediation actions closely
5. **Consider** setting `max_remediation_attempts` conservatively

### Safe Remediation Rollout

```hcl
# Week 1: Detection only
enable_automatic_remediation = false

# Week 2-3: Test with low-risk rules (S3 encryption)
# Enable only specific categories

# Week 4+: Gradually enable all remediations
enable_automatic_remediation = true
```

## Support and Contributions

For issues, questions, or contributions:

1. Review this README and Troubleshooting section
2. Check AWS Config and SSM documentation
3. Review CloudWatch Logs for detailed error messages
4. Open an issue with detailed environment information

## License

[Your License Here]

## References

- [CMMC 2.0 Framework](https://www.acq.osd.mil/cmmc/)
- [AWS Config Developer Guide](https://docs.aws.amazon.com/config/)
- [AWS Config Rules Reference](https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html)
- [SSM Automation Documents](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-automation.html)
