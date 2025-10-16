# AWS Config Recorder
resource "aws_config_configuration_recorder" "main" {
  name     = var.recorder_name
  role_arn = data.aws_iam_role.config.arn

  recording_group {
    all_supported                 = var.all_supported
    include_global_resource_types = var.include_global_resources
    resource_types                = var.resource_types
  }
}

# AWS Config Delivery Channel
resource "aws_config_delivery_channel" "main" {
  name           = var.delivery_channel_name
  s3_bucket_name = aws_s3_bucket.config.id
  s3_key_prefix  = var.s3_key_prefix

  snapshot_delivery_properties {
    delivery_frequency = var.delivery_frequency
  }

  depends_on = [
    aws_config_configuration_recorder.main,
    aws_s3_bucket_policy.config
  ]
}

# Start the Configuration Recorder
resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = var.enable_recorder

  depends_on = [aws_config_delivery_channel.main]
}
