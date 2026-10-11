resource "aws_s3_bucket" "reports" {
  bucket = "acme-reports"
  acl    = "public-read"
}
