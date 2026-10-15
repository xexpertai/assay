variable "enabled" { default = true }
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 8
  encrypted         = false
  count             = var.enabled ? 1 : 0
}
resource "aws_ebs_snapshot" "data" {
  volume_id = aws_ebs_volume.data[0].id
  count     = var.enabled ? 1 : 0
}
data "aws_iam_policy_document" "public" {
  statement {
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.site[0].arn}/*"]
  }
  count = var.enabled ? 1 : 0
}
resource "aws_s3_bucket" "site" {
  bucket_prefix = "site"
  count         = var.enabled ? 1 : 0
}
resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site[0].id
  policy = data.aws_iam_policy_document.public[0].json
  count  = var.enabled ? 1 : 0
}
resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "site" {
  bucket = aws_s3_bucket.site[0].id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_logging" "site" {
  bucket        = aws_s3_bucket.site[0].id
  target_bucket = "logs"
  target_prefix = "site/"
}
resource "aws_s3_bucket_versioning" "site" {
  bucket = aws_s3_bucket.site[0].id
  versioning_configuration { status = "Enabled" }
}
