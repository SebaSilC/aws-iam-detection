resource "aws_config_configuration_recorder" "recorder" {
  name     = "${local.prefix}-config-recorder"
  role_arn = aws_iam_role.lambda_role.arn
}

resource "aws_config_delivery_channel" "channel" {
  name           = "${local.prefix}-config-channel"
  s3_bucket_name = aws_s3_bucket.findings.bucket
}
