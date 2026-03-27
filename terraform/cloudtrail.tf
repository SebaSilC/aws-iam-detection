resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${local.prefix}-cloudtrail-logs"
  force_destroy = true
}

resource "aws_cloudtrail" "main" {
  name                          = "${local.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true

  enable_logging = true
}
