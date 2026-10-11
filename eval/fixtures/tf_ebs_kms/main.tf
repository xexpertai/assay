resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 10
}
resource "aws_ebs_snapshot" "nightly" {
  volume_id = aws_ebs_volume.data.id
}
resource "aws_kms_key" "app" {
  description = "app key"
}
