resource "aws_iam_role_policy" "reader" {
  name = "reader"
  role = "reader-role"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::acme-reports/*"]}
  ]
}
POLICY
}
