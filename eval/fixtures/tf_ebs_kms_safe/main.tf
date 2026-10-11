resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = true
  kms_key_id        = aws_kms_key.app.arn
}
resource "aws_ebs_snapshot" "nightly" {
  volume_id = aws_ebs_volume.data.id
}
resource "aws_kms_key" "app" {
  description         = "app key"
  enable_key_rotation = true
}
