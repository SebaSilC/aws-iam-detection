resource "aws_s3_bucket" "findings" {
  bucket = "${local.prefix}-findings-bucket"

  force_destroy = true
}
