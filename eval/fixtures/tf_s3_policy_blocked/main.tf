resource "aws_s3_bucket" "internal" {
  bucket = "acme-internal"
}
resource "aws_s3_bucket_public_access_block" "internal" {
  bucket                  = aws_s3_bucket.internal.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_policy" "internal" {
  bucket = aws_s3_bucket.internal.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject"]
      Resource  = "${aws_s3_bucket.internal.arn}/*"
      Condition = { StringEquals = { "aws:SourceVpce" = "vpce-0123456789abcdef0" } }
    }]
  })
}
resource "aws_s3_bucket_server_side_encryption_configuration" "internal" {
  bucket = aws_s3_bucket.internal.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}
resource "aws_s3_bucket_logging" "internal" {
  bucket        = aws_s3_bucket.internal.id
  target_bucket = "acme-logs"
  target_prefix = "internal/"
}
resource "aws_s3_bucket_versioning" "internal" {
  bucket = aws_s3_bucket.internal.id
  versioning_configuration { status = "Enabled" }
}
