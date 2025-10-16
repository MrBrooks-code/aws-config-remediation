# CMMC 2.0 Level 2 Config Rules
# Rule definitions for AWS Config conformance pack
# The rules.tf file will automatically inject the AutomationAssumeRole parameter

config_rules = {
  # ============================================================================
  # IAM Rules (16 rules)
  # ============================================================================

  access_keys_rotated = {
    category           = "IAM"
    name               = "access-keys-rotated"
    description        = "Checks whether active access keys are rotated within 90 days"
    source_identifier  = "ACCESS_KEYS_ROTATED"
    input_parameters   = { maxAccessKeyAge = "{{max_access_key_age}}" }
    enable_remediation = false # Requires user action
  }

  iam_password_policy = {
    category          = "IAM"
    name              = "iam-password-policy"
    description       = "Checks whether the account password policy meets specified requirements"
    source_identifier = "IAM_PASSWORD_POLICY"
    input_parameters = {
      RequireUppercaseCharacters = "true"
      RequireLowercaseCharacters = "true"
      RequireSymbols             = "true"
      RequireNumbers             = "true"
      MinimumPasswordLength      = "14"
      PasswordReusePrevention    = "24"
      MaxPasswordAge             = "90"
    }
    enable_remediation = false # Policy setting
  }

  iam_root_access_key_check = {
    category           = "IAM"
    name               = "iam-root-access-key-check"
    description        = "Checks whether root account has active access keys"
    source_identifier  = "IAM_ROOT_ACCESS_KEY_CHECK"
    enable_remediation = false
  }

  iam_user_mfa_enabled = {
    category           = "IAM"
    name               = "iam-user-mfa-enabled"
    description        = "Checks whether IAM users have MFA enabled"
    source_identifier  = "IAM_USER_MFA_ENABLED"
    enable_remediation = false
  }

  mfa_enabled_for_iam_console_access = {
    category           = "IAM"
    name               = "mfa-enabled-for-iam-console-access"
    description        = "Checks whether MFA is enabled for all IAM users with console access"
    source_identifier  = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
    enable_remediation = false
  }

  root_account_hardware_mfa_enabled = {
    category           = "IAM"
    name               = "root-account-hardware-mfa-enabled"
    description        = "Checks whether root account has hardware MFA enabled"
    source_identifier  = "ROOT_ACCOUNT_HARDWARE_MFA_ENABLED"
    enable_remediation = false
  }

  root_account_mfa_enabled = {
    category           = "IAM"
    name               = "root-account-mfa-enabled"
    description        = "Checks whether root account has MFA enabled"
    source_identifier  = "ROOT_ACCOUNT_MFA_ENABLED"
    enable_remediation = false
  }

  iam_user_unused_credentials_check = {
    category          = "IAM"
    name              = "iam-user-unused-credentials-check"
    description       = "Checks whether IAM users have unused credentials for 90 days"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
    input_parameters  = { maxCredentialUsageAge = "90" }
    enable_remediation = false
  }

  iam_user_no_policies_check = {
    category           = "IAM"
    name               = "iam-user-no-policies-check"
    description        = "Checks that IAM users don't have policies attached directly"
    source_identifier  = "IAM_USER_NO_POLICIES_CHECK"
    enable_remediation = false
  }

  iam_policy_no_statements_with_admin_access = {
    category           = "IAM"
    name               = "iam-policy-no-statements-with-admin-access"
    description        = "Checks whether IAM policies grant admin access"
    source_identifier  = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
    enable_remediation = false
  }

  iam_customer_policy_blocked_kms_actions = {
    category          = "IAM"
    name              = "iam-customer-policy-blocked-kms-actions"
    description       = "Checks that customer managed policies don't allow blocked KMS actions"
    source_identifier = "IAM_CUSTOMER_POLICY_BLOCKED_KMS_ACTIONS"
    input_parameters  = { blockedActionsPatterns = "kms:Decrypt,kms:ReEncrypt*" }
    enable_remediation = false
  }

  iam_inline_policy_blocked_kms_actions = {
    category          = "IAM"
    name              = "iam-inline-policy-blocked-kms-actions"
    description       = "Checks that inline policies don't allow blocked KMS actions"
    source_identifier = "IAM_INLINE_POLICY_BLOCKED_KMS_ACTIONS"
    input_parameters  = { blockedActionsPatterns = "kms:Decrypt,kms:ReEncrypt*" }
    enable_remediation = false
  }

  iam_policy_no_statements_with_full_access = {
    category           = "IAM"
    name               = "iam-policy-no-statements-with-full-access"
    description        = "Checks whether IAM policies grant full access"
    source_identifier  = "IAM_POLICY_NO_STATEMENTS_WITH_FULL_ACCESS"
    enable_remediation = false
  }

  iam_group_has_users_check = {
    category           = "IAM"
    name               = "iam-group-has-users-check"
    description        = "Checks whether IAM groups have at least one user"
    source_identifier  = "IAM_GROUP_HAS_USERS_CHECK"
    enable_remediation = false
  }

  iam_user_group_membership_check = {
    category           = "IAM"
    name               = "iam-user-group-membership-check"
    description        = "Checks whether IAM users are members of at least one group"
    source_identifier  = "IAM_USER_GROUP_MEMBERSHIP_CHECK"
    enable_remediation = false
  }

  account_part_of_organizations = {
    category           = "IAM"
    name               = "account-part-of-organizations"
    description        = "Checks whether AWS account is part of AWS Organizations"
    source_identifier  = "ACCOUNT_PART_OF_ORGANIZATIONS"
    enable_remediation = false
  }

  # ============================================================================
  # S3 Rules (10 rules)
  # ============================================================================

  s3_bucket_public_read_prohibited = {
    category           = "S3"
    name               = "s3-bucket-public-read-prohibited"
    description        = "Checks that S3 buckets do not allow public read access"
    source_identifier  = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    resource_types     = ["AWS::S3::Bucket"]
    enable_remediation = true
    ssm_document       = "s3/s3-public-access-block.yaml"
    remediation_parameters = [
      { name = "BucketName", resource_value = "RESOURCE_ID" }
    ]
  }

  s3_bucket_public_write_prohibited = {
    category           = "S3"
    name               = "s3-bucket-public-write-prohibited"
    description        = "Checks that S3 buckets do not allow public write access"
    source_identifier  = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
    resource_types     = ["AWS::S3::Bucket"]
    enable_remediation = true
    ssm_document       = "s3/s3-public-access-block.yaml"
    remediation_parameters = [
      { name = "BucketName", resource_value = "RESOURCE_ID" }
    ]
  }

  s3_bucket_server_side_encryption_enabled = {
    category           = "S3"
    name               = "s3-bucket-server-side-encryption-enabled"
    description        = "Checks that S3 buckets have encryption enabled"
    source_identifier  = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
    resource_types     = ["AWS::S3::Bucket"]
    enable_remediation = true
    ssm_document       = "s3/s3-encryption.yaml"
    remediation_parameters = [
      { name = "BucketName", resource_value = "RESOURCE_ID" }
    ]
  }

  s3_bucket_versioning_enabled = {
    category           = "S3"
    name               = "s3-bucket-versioning-enabled"
    description        = "Checks that S3 buckets have versioning enabled"
    source_identifier  = "S3_BUCKET_VERSIONING_ENABLED"
    resource_types     = ["AWS::S3::Bucket"]
    enable_remediation = true
    ssm_document       = "s3/s3-versioning.yaml"
    remediation_parameters = [
      { name = "BucketName", resource_value = "RESOURCE_ID" }
    ]
  }

  s3_bucket_logging_enabled = {
    category           = "S3"
    name               = "s3-bucket-logging-enabled"
    description        = "Checks that S3 buckets have logging enabled"
    source_identifier  = "S3_BUCKET_LOGGING_ENABLED"
    resource_types     = ["AWS::S3::Bucket"]
    enable_remediation = true # Conditional: only enabled if s3_logging_bucket variable is set
    ssm_document       = "s3/s3-logging.yaml"
    remediation_parameters = [
      { name = "BucketName", resource_value = "RESOURCE_ID" },
      { name = "TargetBucket", static_value = "{{s3_logging_bucket}}" }
    ]
  }

  s3_bucket_ssl_requests_only = {
    category           = "S3"
    name               = "s3-bucket-ssl-requests-only"
    description        = "Checks that S3 buckets have policies requiring SSL"
    source_identifier  = "S3_BUCKET_SSL_REQUESTS_ONLY"
    resource_types     = ["AWS::S3::Bucket"]
    enable_remediation = true
    ssm_document       = "s3/s3-ssl-only.yaml"
    remediation_parameters = [
      { name = "BucketName", resource_value = "RESOURCE_ID" }
    ]
  }

  s3_bucket_default_lock_enabled = {
    category           = "S3"
    name               = "s3-bucket-default-lock-enabled"
    description        = "Checks that S3 buckets have object lock enabled"
    source_identifier  = "S3_BUCKET_DEFAULT_LOCK_ENABLED"
    resource_types     = ["AWS::S3::Bucket"]
    enable_remediation = false # Cannot enable after bucket creation
  }

  s3_bucket_replication_enabled = {
    category           = "S3"
    name               = "s3-bucket-replication-enabled"
    description        = "Checks that S3 buckets have replication enabled"
    source_identifier  = "S3_BUCKET_REPLICATION_ENABLED"
    resource_types     = ["AWS::S3::Bucket"]
    enable_remediation = false # Requires configuration
  }

  s3_default_encryption_kms = {
    category           = "S3"
    name               = "s3-default-encryption-kms"
    description        = "Checks that S3 buckets are encrypted with KMS"
    source_identifier  = "S3_DEFAULT_ENCRYPTION_KMS"
    resource_types     = ["AWS::S3::Bucket"]
    enable_remediation = false # Requires KMS key
  }

  s3_bucket_level_public_access_prohibited = {
    category           = "S3"
    name               = "s3-bucket-level-public-access-prohibited"
    description        = "Checks that S3 bucket level public access is prohibited"
    source_identifier  = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
    resource_types     = ["AWS::S3::Bucket"]
    enable_remediation = true
    ssm_document       = "s3/s3-public-access-block.yaml"
    remediation_parameters = [
      { name = "BucketName", resource_value = "RESOURCE_ID" }
    ]
  }

  # ============================================================================
  # EC2 Rules (15 rules)
  # ============================================================================

  ec2_ebs_encryption_by_default = {
    category           = "EC2"
    name               = "ec2-ebs-encryption-by-default"
    description        = "Checks that EBS encryption is enabled by default"
    source_identifier  = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
    enable_remediation = true
    ssm_document       = "ec2/ebs-encryption-by-default.yaml"
    remediation_parameters = []
  }

  encrypted_volumes = {
    category           = "EC2"
    name               = "encrypted-volumes"
    description        = "Checks whether EBS volumes are encrypted"
    source_identifier  = "ENCRYPTED_VOLUMES"
    resource_types     = ["AWS::EC2::Volume"]
    enable_remediation = false # Cannot encrypt existing volume
  }

  ec2_instance_no_public_ip = {
    category           = "EC2"
    name               = "ec2-instance-no-public-ip"
    description        = "Checks that EC2 instances don't have public IPs"
    source_identifier  = "EC2_INSTANCE_NO_PUBLIC_IP"
    resource_types     = ["AWS::EC2::Instance"]
    enable_remediation = false
  }

  ec2_instance_managed_by_systems_manager = {
    category           = "EC2"
    name               = "ec2-instance-managed-by-systems-manager"
    description        = "Checks that EC2 instances are managed by Systems Manager"
    source_identifier  = "EC2_INSTANCE_MANAGED_BY_SSM"
    resource_types     = ["AWS::EC2::Instance"]
    enable_remediation = false
  }

  ec2_managedinstance_association_compliance_status_check = {
    category           = "EC2"
    name               = "ec2-managedinstance-association-compliance-status-check"
    description        = "Checks that Systems Manager association compliance status is COMPLIANT"
    source_identifier  = "EC2_MANAGEDINSTANCE_ASSOCIATION_COMPLIANCE_STATUS_CHECK"
    enable_remediation = false
  }

  ec2_volume_inuse_check = {
    category          = "EC2"
    name              = "ec2-volume-inuse-check"
    description       = "Checks that EBS volumes are attached to EC2 instances"
    source_identifier = "EC2_VOLUME_INUSE_CHECK"
    resource_types    = ["AWS::EC2::Volume"]
    input_parameters  = { deleteOnTermination = "true" }
    enable_remediation = false
  }

  ec2_instances_in_vpc = {
    category           = "EC2"
    name               = "ec2-instances-in-vpc"
    description        = "Checks that EC2 instances are in a VPC"
    source_identifier  = "INSTANCES_IN_VPC"
    resource_types     = ["AWS::EC2::Instance"]
    enable_remediation = false
  }

  ec2_stopped_instance = {
    category           = "EC2"
    name               = "ec2-stopped-instance"
    description        = "Checks that EC2 instances are not stopped for more than allowed time"
    source_identifier  = "EC2_STOPPED_INSTANCE"
    resource_types     = ["AWS::EC2::Instance"]
    enable_remediation = false
  }

  ebs_optimized_instance = {
    category           = "EC2"
    name               = "ebs-optimized-instance"
    description        = "Checks that EBS optimization is enabled for EC2 instances"
    source_identifier  = "EBS_OPTIMIZED_INSTANCE"
    resource_types     = ["AWS::EC2::Instance"]
    enable_remediation = false
  }

  ec2_imdsv2_check = {
    category           = "EC2"
    name               = "ec2-imdsv2-check"
    description        = "Checks that EC2 instances use IMDSv2"
    source_identifier  = "EC2_IMDSV2_CHECK"
    resource_types     = ["AWS::EC2::Instance"]
    enable_remediation = false
  }

  autoscaling_launch_config_public_ip_disabled = {
    category           = "EC2"
    name               = "autoscaling-launch-config-public-ip-disabled"
    description        = "Checks that Auto Scaling launch configurations don't assign public IPs"
    source_identifier  = "AUTOSCALING_LAUNCH_CONFIG_PUBLIC_IP_DISABLED"
    enable_remediation = false
  }

  ec2_security_group_attached_to_eni = {
    category           = "EC2"
    name               = "ec2-security-group-attached-to-eni"
    description        = "Checks that security groups are attached to ENIs"
    source_identifier  = "EC2_SECURITY_GROUP_ATTACHED_TO_ENI"
    enable_remediation = false
  }

  eip_attached = {
    category           = "EC2"
    name               = "eip-attached"
    description        = "Checks that Elastic IPs are attached to instances"
    source_identifier  = "EIP_ATTACHED"
    enable_remediation = false
  }

  autoscaling_group_elb_healthcheck_required = {
    category           = "EC2"
    name               = "autoscaling-group-elb-healthcheck-required"
    description        = "Checks that Auto Scaling groups use ELB health checks"
    source_identifier  = "AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED"
    enable_remediation = false
  }

  ec2_instance_detailed_monitoring_enabled = {
    category           = "EC2"
    name               = "ec2-instance-detailed-monitoring-enabled"
    description        = "Checks that EC2 instances have detailed monitoring enabled"
    source_identifier  = "EC2_INSTANCE_DETAILED_MONITORING_ENABLED"
    resource_types     = ["AWS::EC2::Instance"]
    enable_remediation = false
  }

  # ============================================================================
  # RDS Rules (10 rules)
  # ============================================================================

  rds_storage_encrypted = {
    category           = "RDS"
    name               = "rds-storage-encrypted"
    description        = "Checks that RDS instances have encryption enabled"
    source_identifier  = "RDS_STORAGE_ENCRYPTED"
    resource_types     = ["AWS::RDS::DBInstance"]
    enable_remediation = false # Cannot enable after creation
  }

  rds_automatic_minor_version_upgrade_enabled = {
    category           = "RDS"
    name               = "rds-automatic-minor-version-upgrade-enabled"
    description        = "Checks that RDS instances have automatic minor version upgrades enabled"
    source_identifier  = "RDS_AUTOMATIC_MINOR_VERSION_UPGRADE_ENABLED"
    resource_types     = ["AWS::RDS::DBInstance"]
    enable_remediation = true
    ssm_document       = "rds/rds-enable-minor-version-upgrade.yaml"
    remediation_parameters = [
      { name = "DbInstanceId", resource_value = "RESOURCE_ID" }
    ]
  }

  db_instance_backup_enabled = {
    category           = "RDS"
    name               = "db-instance-backup-enabled"
    description        = "Checks that RDS instances have automated backups enabled"
    source_identifier  = "DB_INSTANCE_BACKUP_ENABLED"
    resource_types     = ["AWS::RDS::DBInstance"]
    enable_remediation = true
    ssm_document       = "rds/rds-enable-backups.yaml"
    remediation_parameters = [
      { name = "DbInstanceId", resource_value = "RESOURCE_ID" }
    ]
  }

  rds_multi_az_support = {
    category           = "RDS"
    name               = "rds-multi-az-support"
    description        = "Checks that RDS instances have Multi-AZ enabled"
    source_identifier  = "RDS_MULTI_AZ_SUPPORT"
    resource_types     = ["AWS::RDS::DBInstance"]
    enable_remediation = false # Requires downtime
  }

  rds_instance_deletion_protection_enabled = {
    category           = "RDS"
    name               = "rds-instance-deletion-protection-enabled"
    description        = "Checks that RDS instances have deletion protection enabled"
    source_identifier  = "RDS_INSTANCE_DELETION_PROTECTION_ENABLED"
    resource_types     = ["AWS::RDS::DBInstance"]
    enable_remediation = true
    ssm_document       = "rds/rds-enable-deletion-protection.yaml"
    remediation_parameters = [
      { name = "DbInstanceId", resource_value = "RESOURCE_ID" }
    ]
  }

  rds_instance_public_access_check = {
    category           = "RDS"
    name               = "rds-instance-public-access-check"
    description        = "Checks that RDS instances are not publicly accessible"
    source_identifier  = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
    resource_types     = ["AWS::RDS::DBInstance"]
    enable_remediation = false
  }

  rds_logging_enabled = {
    category           = "RDS"
    name               = "rds-logging-enabled"
    description        = "Checks that RDS instances have logging enabled"
    source_identifier  = "RDS_LOGGING_ENABLED"
    resource_types     = ["AWS::RDS::DBInstance"]
    enable_remediation = false
  }

  rds_snapshots_public_prohibited = {
    category           = "RDS"
    name               = "rds-snapshots-public-prohibited"
    description        = "Checks that RDS snapshots are not public"
    source_identifier  = "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"
    enable_remediation = true
    ssm_document       = "rds/rds-snapshot-make-private.yaml"
    remediation_parameters = [
      { name = "DbSnapshotId", resource_value = "RESOURCE_ID" }
    ]
  }

  rds_cluster_deletion_protection_enabled = {
    category           = "RDS"
    name               = "rds-cluster-deletion-protection-enabled"
    description        = "Checks that RDS clusters have deletion protection enabled"
    source_identifier  = "RDS_CLUSTER_DELETION_PROTECTION_ENABLED"
    resource_types     = ["AWS::RDS::DBCluster"]
    enable_remediation = false
  }

  rds_enhanced_monitoring_enabled = {
    category           = "RDS"
    name               = "rds-enhanced-monitoring-enabled"
    description        = "Checks that RDS instances have enhanced monitoring enabled"
    source_identifier  = "RDS_ENHANCED_MONITORING_ENABLED"
    resource_types     = ["AWS::RDS::DBInstance"]
    enable_remediation = false
  }

  # ============================================================================
  # CloudTrail & Logging Rules (7 rules)
  # ============================================================================

  cloudtrail_enabled = {
    category           = "CloudTrail"
    name               = "cloudtrail-enabled"
    description        = "Checks that CloudTrail is enabled"
    source_identifier  = "CLOUD_TRAIL_ENABLED"
    enable_remediation = false # Account-level setting
  }

  cloud_trail_encryption_enabled = {
    category           = "CloudTrail"
    name               = "cloud-trail-encryption-enabled"
    description        = "Checks that CloudTrail logs are encrypted"
    source_identifier  = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
    enable_remediation = true # Conditional: only enabled if cloudtrail_kms_key_id variable is set
    ssm_document       = "cloudtrail/cloudtrail-enable-encryption.yaml"
    remediation_parameters = [
      { name = "TrailName", resource_value = "RESOURCE_ID" },
      { name = "KmsKeyId", static_value = "{{cloudtrail_kms_key_id}}" }
    ]
  }

  cloud_trail_log_file_validation_enabled = {
    category           = "CloudTrail"
    name               = "cloud-trail-log-file-validation-enabled"
    description        = "Checks that CloudTrail log file validation is enabled"
    source_identifier  = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
    enable_remediation = true
    ssm_document       = "cloudtrail/cloudtrail-enable-log-validation.yaml"
    remediation_parameters = [
      { name = "TrailName", resource_value = "RESOURCE_ID" }
    ]
  }

  cloud_trail_cloud_watch_logs_enabled = {
    category           = "CloudTrail"
    name               = "cloud-trail-cloud-watch-logs-enabled"
    description        = "Checks that CloudTrail sends logs to CloudWatch"
    source_identifier  = "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED"
    enable_remediation = false
  }

  cloudtrail_s3_dataevents_enabled = {
    category           = "CloudTrail"
    name               = "cloudtrail-s3-dataevents-enabled"
    description        = "Checks that CloudTrail logs S3 data events"
    source_identifier  = "CLOUDTRAIL_S3_DATAEVENTS_ENABLED"
    enable_remediation = false
  }

  multi_region_cloud_trail_enabled = {
    category           = "CloudTrail"
    name               = "multi-region-cloud-trail-enabled"
    description        = "Checks that CloudTrail is enabled in all regions"
    source_identifier  = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
    enable_remediation = false
  }

  cw_loggroup_retention_period_check = {
    category          = "CloudTrail"
    name              = "cw-loggroup-retention-period-check"
    description       = "Checks that CloudWatch log groups have sufficient retention"
    source_identifier = "CW_LOGGROUP_RETENTION_PERIOD_CHECK"
    input_parameters  = { MinRetentionTime = "{{log_retention_days}}" }
    enable_remediation = true
    ssm_document       = "cloudtrail/cloudwatch-set-retention.yaml"
    remediation_parameters = [
      { name = "LogGroupName", resource_value = "RESOURCE_ID" },
      { name = "RetentionInDays", static_value = "{{log_retention_days}}" }
    ]
  }

  # ============================================================================
  # KMS Rules (8 rules)
  # ============================================================================

  cmk_backing_key_rotation_enabled = {
    category           = "KMS"
    name               = "cmk-backing-key-rotation-enabled"
    description        = "Checks that KMS CMK key rotation is enabled"
    source_identifier  = "CMK_BACKING_KEY_ROTATION_ENABLED"
    resource_types     = ["AWS::KMS::Key"]
    enable_remediation = true
    ssm_document       = "kms/kms-enable-key-rotation.yaml"
    remediation_parameters = [
      { name = "KeyId", resource_value = "RESOURCE_ID" }
    ]
  }

  kms_cmk_not_scheduled_for_deletion = {
    category           = "KMS"
    name               = "kms-cmk-not-scheduled-for-deletion"
    description        = "Checks that KMS CMKs are not scheduled for deletion"
    source_identifier  = "KMS_CMK_NOT_SCHEDULED_FOR_DELETION"
    resource_types     = ["AWS::KMS::Key"]
    enable_remediation = false
  }

  sns_encrypted_kms = {
    category           = "KMS"
    name               = "sns-encrypted-kms"
    description        = "Checks that SNS topics are encrypted with KMS"
    source_identifier  = "SNS_ENCRYPTED_KMS"
    resource_types     = ["AWS::SNS::Topic"]
    enable_remediation = false
  }

  elasticsearch_encrypted_at_rest = {
    category           = "KMS"
    name               = "elasticsearch-encrypted-at-rest"
    description        = "Checks that Elasticsearch domains are encrypted at rest"
    source_identifier  = "ELASTICSEARCH_ENCRYPTED_AT_REST"
    enable_remediation = false
  }

  dynamodb_table_encrypted_kms = {
    category           = "KMS"
    name               = "dynamodb-table-encrypted-kms"
    description        = "Checks that DynamoDB tables are encrypted with KMS"
    source_identifier  = "DYNAMODB_TABLE_ENCRYPTED_KMS"
    resource_types     = ["AWS::DynamoDB::Table"]
    enable_remediation = false
  }

  sagemaker_endpoint_configuration_kms_key_configured = {
    category           = "KMS"
    name               = "sagemaker-endpoint-configuration-kms-key-configured"
    description        = "Checks that SageMaker endpoints are encrypted with KMS"
    source_identifier  = "SAGEMAKER_ENDPOINT_CONFIGURATION_KMS_KEY_CONFIGURED"
    enable_remediation = false
  }

  sagemaker_notebook_instance_kms_key_configured = {
    category           = "KMS"
    name               = "sagemaker-notebook-instance-kms-key-configured"
    description        = "Checks that SageMaker notebooks are encrypted with KMS"
    source_identifier  = "SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED"
    enable_remediation = false
  }

  secretsmanager_using_cmk = {
    category           = "KMS"
    name               = "secretsmanager-using-cmk"
    description        = "Checks that Secrets Manager uses customer-managed keys"
    source_identifier  = "SECRETSMANAGER_USING_CMK"
    enable_remediation = false
  }

  # ============================================================================
  # VPC & Network Rules (6 rules)
  # ============================================================================

  vpc_sg_open_only_to_authorized_ports = {
    category           = "VPC"
    name               = "vpc-sg-open-only-to-authorized-ports"
    description        = "Checks that security groups only allow authorized ports"
    source_identifier  = "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS"
    enable_remediation = false
  }

  restricted_ssh = {
    category           = "VPC"
    name               = "restricted-ssh"
    description        = "Checks that security groups don't allow unrestricted SSH"
    source_identifier  = "INCOMING_SSH_DISABLED"
    enable_remediation = true
    ssm_document       = "securitygroup/sg-remove-unrestricted-ssh.yaml"
    remediation_parameters = [
      { name = "SecurityGroupId", resource_value = "RESOURCE_ID" }
    ]
  }

  restricted_common_ports = {
    category           = "VPC"
    name               = "restricted-common-ports"
    description        = "Checks that security groups don't allow unrestricted access to common ports"
    source_identifier  = "RESTRICTED_INCOMING_TRAFFIC"
    enable_remediation = false
  }

  vpc_default_security_group_closed = {
    category           = "VPC"
    name               = "vpc-default-security-group-closed"
    description        = "Checks that default security groups don't allow traffic"
    source_identifier  = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
    enable_remediation = false
  }

  vpc_flow_logs_enabled = {
    category           = "VPC"
    name               = "vpc-flow-logs-enabled"
    description        = "Checks that VPC flow logs are enabled"
    source_identifier  = "VPC_FLOW_LOGS_ENABLED"
    resource_types     = ["AWS::EC2::VPC"]
    enable_remediation = false
  }

  subnet_auto_assign_public_ip_disabled = {
    category           = "VPC"
    name               = "subnet-auto-assign-public-ip-disabled"
    description        = "Checks that subnets don't auto-assign public IPs"
    source_identifier  = "SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED"
    enable_remediation = false
  }

  # Commented out: Requires customer-specific VPC IDs to be configured
  # internet_gateway_authorized_vpc_only = {
  #   category          = "VPC"
  #   name              = "internet-gateway-authorized-vpc-only"
  #   description       = "Checks that internet gateways are only attached to authorized VPCs"
  #   source_identifier = "INTERNET_GATEWAY_AUTHORIZED_VPC_ONLY"
  #   input_parameters  = { AuthorizedVpcIds = var.authorized_vpc_ids }
  #   enable_remediation = false
  # }

  # ============================================================================
  # Load Balancer Rules (8 rules)
  # ============================================================================

  alb_http_to_https_redirection_check = {
    category           = "ELB"
    name               = "alb-http-to-https-redirection-check"
    description        = "Checks that ALBs redirect HTTP to HTTPS"
    source_identifier  = "ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK"
    enable_remediation = false
  }

  alb_http_drop_invalid_header_enabled = {
    category           = "ELB"
    name               = "alb-http-drop-invalid-header-enabled"
    description        = "Checks that ALBs drop invalid HTTP headers"
    source_identifier  = "ALB_HTTP_DROP_INVALID_HEADER_ENABLED"
    enable_remediation = false
  }

  alb_waf_enabled = {
    category           = "ELB"
    name               = "alb-waf-enabled"
    description        = "Checks that ALBs have WAF enabled"
    source_identifier  = "ALB_WAF_ENABLED"
    enable_remediation = false
  }

  elb_logging_enabled = {
    category           = "ELB"
    name               = "elb-logging-enabled"
    description        = "Checks that ELBs have logging enabled"
    source_identifier  = "ELB_LOGGING_ENABLED"
    enable_remediation = false
  }

  elb_deletion_protection_enabled = {
    category           = "ELB"
    name               = "elb-deletion-protection-enabled"
    description        = "Checks that ELBs have deletion protection enabled"
    source_identifier  = "ELB_DELETION_PROTECTION_ENABLED"
    enable_remediation = false
  }

  elb_tls_https_listeners_only = {
    category           = "ELB"
    name               = "elb-tls-https-listeners-only"
    description        = "Checks that ELBs only use HTTPS listeners"
    source_identifier  = "ELB_TLS_HTTPS_LISTENERS_ONLY"
    enable_remediation = false
  }

  elbv2_acm_certificate_required = {
    category           = "ELB"
    name               = "elbv2-acm-certificate-required"
    description        = "Checks that ELBv2 uses ACM certificates"
    source_identifier  = "ELBV2_ACM_CERTIFICATE_REQUIRED"
    enable_remediation = false
  }

  elb_cross_zone_load_balancing_enabled = {
    category           = "ELB"
    name               = "elb-cross-zone-load-balancing-enabled"
    description        = "Checks that classic ELBs have cross-zone load balancing enabled"
    source_identifier  = "ELB_CROSS_ZONE_LOAD_BALANCING_ENABLED"
    enable_remediation = false
  }

  # ============================================================================
  # Backup & DR Rules (5 rules)
  # ============================================================================

  backup_plan_min_frequency_and_min_retention_check = {
    category          = "Backup"
    name              = "backup-plan-min-frequency-and-min-retention-check"
    description       = "Checks that backup plans meet minimum frequency and retention"
    source_identifier = "BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK"
    input_parameters = {
      requiredFrequencyUnit  = "days"
      requiredFrequencyValue = "1"
      requiredRetentionDays  = "35"
    }
    enable_remediation = false
  }

  dynamodb_pitr_enabled = {
    category           = "Backup"
    name               = "dynamodb-pitr-enabled"
    description        = "Checks that DynamoDB tables have point-in-time recovery enabled"
    source_identifier  = "DYNAMODB_PITR_ENABLED"
    resource_types     = ["AWS::DynamoDB::Table"]
    enable_remediation = false
  }

  elasticache_redis_cluster_automatic_backup_check = {
    category           = "Backup"
    name               = "elasticache-redis-cluster-automatic-backup-check"
    description        = "Checks that ElastiCache Redis clusters have automatic backups"
    source_identifier  = "ELASTICACHE_REDIS_CLUSTER_AUTOMATIC_BACKUP_CHECK"
    enable_remediation = false
  }

  redshift_backup_enabled = {
    category           = "Backup"
    name               = "redshift-backup-enabled"
    description        = "Checks that Redshift clusters have automated backups enabled"
    source_identifier  = "REDSHIFT_BACKUP_ENABLED"
    enable_remediation = false
  }

  efs_in_backup_plan = {
    category           = "Backup"
    name               = "efs-in-backup-plan"
    description        = "Checks that EFS file systems are in a backup plan"
    source_identifier  = "EFS_IN_BACKUP_PLAN"
    enable_remediation = false
  }

  # ============================================================================
  # Lambda Rules (4 rules)
  # ============================================================================

  lambda_function_public_access_prohibited = {
    category           = "Lambda"
    name               = "lambda-function-public-access-prohibited"
    description        = "Checks that Lambda functions don't allow public access"
    source_identifier  = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
    resource_types     = ["AWS::Lambda::Function"]
    enable_remediation = false
  }

  # Commented out: Requires runtime parameter (e.g., python3.11,nodejs20.x)
  # lambda_function_settings_check = {
  #   category           = "Lambda"
  #   name               = "lambda-function-settings-check"
  #   description        = "Checks that Lambda functions are properly configured"
  #   source_identifier  = "LAMBDA_FUNCTION_SETTINGS_CHECK"
  #   resource_types     = ["AWS::Lambda::Function"]
  #   input_parameters   = { runtime = "python3.11,nodejs20.x,java17" }
  #   enable_remediation = false
  # }

  lambda_inside_vpc = {
    category           = "Lambda"
    name               = "lambda-inside-vpc"
    description        = "Checks that Lambda functions are in a VPC"
    source_identifier  = "LAMBDA_INSIDE_VPC"
    resource_types     = ["AWS::Lambda::Function"]
    enable_remediation = false
  }

  lambda_concurrency_check = {
    category           = "Lambda"
    name               = "lambda-concurrency-check"
    description        = "Checks that Lambda functions have reserved concurrency"
    source_identifier  = "LAMBDA_CONCURRENCY_CHECK"
    resource_types     = ["AWS::Lambda::Function"]
    enable_remediation = false
  }

  lambda_dlq_check = {
    category           = "Lambda"
    name               = "lambda-dlq-check"
    description        = "Checks that Lambda functions have dead letter queues configured"
    source_identifier  = "LAMBDA_DLQ_CHECK"
    resource_types     = ["AWS::Lambda::Function"]
    enable_remediation = false
  }

  # ============================================================================
  # API Gateway Rules (5 rules)
  # ============================================================================

  api_gw_associated_with_waf = {
    category           = "APIGateway"
    name               = "api-gw-associated-with-waf"
    description        = "Checks that API Gateway is associated with WAF"
    source_identifier  = "API_GW_ASSOCIATED_WITH_WAF"
    enable_remediation = false
  }

  api_gw_cache_enabled_and_encrypted = {
    category           = "APIGateway"
    name               = "api-gw-cache-enabled-and-encrypted"
    description        = "Checks that API Gateway cache is enabled and encrypted"
    source_identifier  = "API_GW_CACHE_ENABLED_AND_ENCRYPTED"
    enable_remediation = false
  }

  api_gw_execution_logging_enabled = {
    category           = "APIGateway"
    name               = "api-gw-execution-logging-enabled"
    description        = "Checks that API Gateway has execution logging enabled"
    source_identifier  = "API_GW_EXECUTION_LOGGING_ENABLED"
    enable_remediation = false
  }

  api_gw_ssl_enabled = {
    category           = "APIGateway"
    name               = "api-gw-ssl-enabled"
    description        = "Checks that API Gateway uses SSL certificates"
    source_identifier  = "API_GW_SSL_ENABLED"
    enable_remediation = false
  }

  api_gw_xray_enabled = {
    category           = "APIGateway"
    name               = "api-gw-xray-enabled"
    description        = "Checks that API Gateway has X-Ray tracing enabled"
    source_identifier  = "API_GW_XRAY_ENABLED"
    enable_remediation = false
  }

  # ============================================================================
  # CloudWatch Rules (0 active rules - all commented out)
  # ============================================================================

  # Commented out: Requires alarm action parameters
  # cloudwatch_alarm_action_check = {
  #   category           = "CloudWatch"
  #   name               = "cloudwatch-alarm-action-check"
  #   description        = "Checks that CloudWatch alarms have actions configured"
  #   source_identifier  = "CLOUDWATCH_ALARM_ACTION_CHECK"
  #   input_parameters   = {
  #     alarmActionRequired = "true"
  #     insufficientDataActionRequired = "false"
  #     okActionRequired = "false"
  #   }
  #   enable_remediation = false
  # }

  # Commented out: Requires resourceType and metricName parameters
  # cloudwatch_alarm_resource_check = {
  #   category           = "CloudWatch"
  #   name               = "cloudwatch-alarm-resource-check"
  #   description        = "Checks that resources have CloudWatch alarms"
  #   source_identifier  = "CLOUDWATCH_ALARM_RESOURCE_CHECK"
  #   input_parameters   = {
  #     resourceType = "AWS::EC2::Instance"
  #     metricName = "CPUUtilization"
  #   }
  #   enable_remediation = false
  # }

  # Commented out: Requires metricName parameter
  # cloudwatch_alarm_settings_check = {
  #   category           = "CloudWatch"
  #   name               = "cloudwatch-alarm-settings-check"
  #   description        = "Checks that CloudWatch alarms are properly configured"
  #   source_identifier  = "CLOUDWATCH_ALARM_SETTINGS_CHECK"
  #   input_parameters   = { metricName = "CPUUtilization" }
  #   enable_remediation = false
  # }

  # ============================================================================
  # Other Service Rules (27 rules)
  # ============================================================================

  acm_certificate_expiration_check = {
    category          = "ACM"
    name              = "acm-certificate-expiration-check"
    description       = "Checks that ACM certificates are not expiring soon"
    source_identifier = "ACM_CERTIFICATE_EXPIRATION_CHECK"
    input_parameters  = { daysToExpiration = "{{certificate_expiration_days}}" }
    enable_remediation = false
  }

  guardduty_enabled_centralized = {
    category           = "GuardDuty"
    name               = "guardduty-enabled-centralized"
    description        = "Checks that GuardDuty is enabled"
    source_identifier  = "GUARDDUTY_ENABLED_CENTRALIZED"
    enable_remediation = false
  }

  guardduty_non_archived_findings = {
    category          = "GuardDuty"
    name              = "guardduty-non-archived-findings"
    description       = "Checks for non-archived GuardDuty findings"
    source_identifier = "GUARDDUTY_NON_ARCHIVED_FINDINGS"
    input_parameters = {
      daysLowSev    = "30"
      daysMediumSev = "7"
      daysHighSev   = "1"
    }
    enable_remediation = false
  }

  securityhub_enabled = {
    category           = "SecurityHub"
    name               = "securityhub-enabled"
    description        = "Checks that Security Hub is enabled"
    source_identifier  = "SECURITYHUB_ENABLED"
    enable_remediation = false
  }

  codebuild_project_envvar_awscred_check = {
    category           = "CodeBuild"
    name               = "codebuild-project-envvar-awscred-check"
    description        = "Checks that CodeBuild doesn't expose AWS credentials in environment variables"
    source_identifier  = "CODEBUILD_PROJECT_ENVVAR_AWSCRED_CHECK"
    enable_remediation = false
  }

  codebuild_project_source_repo_url_check = {
    category           = "CodeBuild"
    name               = "codebuild-project-source-repo-url-check"
    description        = "Checks that CodeBuild source repo URLs are approved"
    source_identifier  = "CODEBUILD_PROJECT_SOURCE_REPO_URL_CHECK"
    enable_remediation = false
  }

  secretsmanager_rotation_enabled_check = {
    category           = "SecretsManager"
    name               = "secretsmanager-rotation-enabled-check"
    description        = "Checks that Secrets Manager secrets have rotation enabled"
    source_identifier  = "SECRETSMANAGER_ROTATION_ENABLED_CHECK"
    enable_remediation = false
  }

  secretsmanager_scheduled_rotation_success_check = {
    category           = "SecretsManager"
    name               = "secretsmanager-scheduled-rotation-success-check"
    description        = "Checks that Secrets Manager rotation succeeds"
    source_identifier  = "SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK"
    enable_remediation = false
  }

  dynamodb_autoscaling_enabled = {
    category           = "DynamoDB"
    name               = "dynamodb-autoscaling-enabled"
    description        = "Checks that DynamoDB tables have auto scaling enabled"
    source_identifier  = "DYNAMODB_AUTOSCALING_ENABLED"
    resource_types     = ["AWS::DynamoDB::Table"]
    enable_remediation = false
  }

  dynamodb_throughput_limit_check = {
    category           = "DynamoDB"
    name               = "dynamodb-throughput-limit-check"
    description        = "Checks that DynamoDB provisioned throughput is within limits"
    source_identifier  = "DYNAMODB_THROUGHPUT_LIMIT_CHECK"
    resource_types     = ["AWS::DynamoDB::Table"]
    enable_remediation = false
  }

  dax_encryption_enabled = {
    category           = "DynamoDB"
    name               = "dax-encryption-enabled"
    description        = "Checks that DAX clusters have encryption enabled"
    source_identifier  = "DAX_ENCRYPTION_ENABLED"
    enable_remediation = false
  }

  redshift_cluster_configuration_check = {
    category           = "Redshift"
    name               = "redshift-cluster-configuration-check"
    description        = "Checks that Redshift clusters are properly configured"
    source_identifier  = "REDSHIFT_CLUSTER_CONFIGURATION_CHECK"
    input_parameters   = {
      clusterDbEncrypted = "true"
      loggingEnabled     = "true"
    }
    enable_remediation = false
  }

  redshift_cluster_public_access_check = {
    category           = "Redshift"
    name               = "redshift-cluster-public-access-check"
    description        = "Checks that Redshift clusters are not publicly accessible"
    source_identifier  = "REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK"
    enable_remediation = false
  }

  redshift_require_tls_ssl = {
    category           = "Redshift"
    name               = "redshift-require-tls-ssl"
    description        = "Checks that Redshift requires TLS/SSL"
    source_identifier  = "REDSHIFT_REQUIRE_TLS_SSL"
    enable_remediation = false
  }

  redshift_enhanced_vpc_routing_enabled = {
    category           = "Redshift"
    name               = "redshift-enhanced-vpc-routing-enabled"
    description        = "Checks that Redshift has enhanced VPC routing enabled"
    source_identifier  = "REDSHIFT_ENHANCED_VPC_ROUTING_ENABLED"
    enable_remediation = false
  }

  redshift_cluster_maintenancesettings_check = {
    category          = "Redshift"
    name              = "redshift-cluster-maintenancesettings-check"
    description       = "Checks that Redshift maintenance settings are configured"
    source_identifier = "REDSHIFT_CLUSTER_MAINTENANCESETTINGS_CHECK"
    input_parameters  = { allowVersionUpgrade = "true" }
    enable_remediation = false
  }

  waf_regional_webacl_not_empty = {
    category           = "WAF"
    name               = "waf-regional-webacl-not-empty"
    description        = "Checks that WAF regional web ACLs are not empty"
    source_identifier  = "WAF_REGIONAL_WEBACL_NOT_EMPTY"
    enable_remediation = false
  }

  wafv2_logging_enabled = {
    category           = "WAF"
    name               = "wafv2-logging-enabled"
    description        = "Checks that WAFv2 logging is enabled"
    source_identifier  = "WAFV2_LOGGING_ENABLED"
    enable_remediation = false
  }

  opensearch_encrypted_at_rest = {
    category           = "OpenSearch"
    name               = "opensearch-encrypted-at-rest"
    description        = "Checks that OpenSearch domains are encrypted at rest"
    source_identifier  = "OPENSEARCH_ENCRYPTED_AT_REST"
    enable_remediation = false
  }

  opensearch_in_vpc_only = {
    category           = "OpenSearch"
    name               = "opensearch-in-vpc-only"
    description        = "Checks that OpenSearch domains are in a VPC"
    source_identifier  = "OPENSEARCH_IN_VPC_ONLY"
    enable_remediation = false
  }

  opensearch_node_to_node_encryption_check = {
    category           = "OpenSearch"
    name               = "opensearch-node-to-node-encryption-check"
    description        = "Checks that OpenSearch has node-to-node encryption"
    source_identifier  = "OPENSEARCH_NODE_TO_NODE_ENCRYPTION_CHECK"
    enable_remediation = false
  }

  elasticsearch_in_vpc_only = {
    category           = "Elasticsearch"
    name               = "elasticsearch-in-vpc-only"
    description        = "Checks that Elasticsearch domains are in a VPC"
    source_identifier  = "ELASTICSEARCH_IN_VPC_ONLY"
    enable_remediation = false
  }

  elasticsearch_node_to_node_encryption_check = {
    category           = "Elasticsearch"
    name               = "elasticsearch-node-to-node-encryption-check"
    description        = "Checks that Elasticsearch has node-to-node encryption"
    source_identifier  = "ELASTICSEARCH_NODE_TO_NODE_ENCRYPTION_CHECK"
    enable_remediation = false
  }

  efs_encrypted_check = {
    category           = "EFS"
    name               = "efs-encrypted-check"
    description        = "Checks that EFS file systems are encrypted"
    source_identifier  = "EFS_ENCRYPTED_CHECK"
    enable_remediation = false
  }

  sagemaker_notebook_no_direct_internet_access = {
    category           = "SageMaker"
    name               = "sagemaker-notebook-no-direct-internet-access"
    description        = "Checks that SageMaker notebooks don't have direct internet access"
    source_identifier  = "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS"
    enable_remediation = false
  }

  vpc_vpn_2_tunnels_up = {
    category           = "VPN"
    name               = "vpc-vpn-2-tunnels-up"
    description        = "Checks that VPN connections have 2 tunnels up"
    source_identifier  = "VPC_VPN_2_TUNNELS_UP"
    enable_remediation = false
  }

  # Commented out: Requires instanceType parameter with approved instance types
  # desired_instance_type = {
  #   category           = "EC2"
  #   name               = "desired-instance-type"
  #   description        = "Checks that EC2 instances are of approved types"
  #   source_identifier  = "DESIRED_INSTANCE_TYPE"
  #   resource_types     = ["AWS::EC2::Instance"]
  #   input_parameters   = { instanceType = "t3.micro,t3.small,m5.large" }
  #   enable_remediation = false
  # }

  # Commented out: Requires amiIds parameter with approved AMI IDs
  # approved_amis_by_id = {
  #   category           = "EC2"
  #   name               = "approved-amis-by-id"
  #   description        = "Checks that EC2 instances use approved AMIs"
  #   source_identifier  = "APPROVED_AMIS_BY_ID"
  #   resource_types     = ["AWS::EC2::Instance"]
  #   input_parameters   = { amiIds = "ami-12345678,ami-87654321" }
  #   enable_remediation = false
  # }
}
