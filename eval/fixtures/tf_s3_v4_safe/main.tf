resource "aws_s3_bucket" "exports" {
  bucket = "acme-exports"
}
resource "aws_s3_bucket_acl" "exports" {
  bucket = aws_s3_bucket.exports.id
  acl    = "private"
}
resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_policy" "exports" {
  bucket = aws_s3_bucket.exports.id
  policy = <<-POLICY
  {
    "Version": "2012-10-17",
    "Statement": [
      {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "${aws_s3_bucket.exports.arn}/*",
       "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
      {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/reporting"},
       "Action": ["s3:GetObject"], "Resource": "${aws_s3_bucket.exports.arn}/*"}
    ]
  }
  POLICY
}
resource "aws_s3_bucket_server_side_encryption_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
resource "aws_s3_bucket_logging" "exports" {
  bucket        = aws_s3_bucket.exports.id
  target_bucket = "acme-logs"
  target_prefix = "exports/"
}
resource "aws_s3_bucket_versioning" "exports" {
  bucket = aws_s3_bucket.exports.id
  versioning_configuration {
    status = "Enabled"
  }
}
