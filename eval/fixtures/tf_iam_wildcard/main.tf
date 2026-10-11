resource "aws_iam_role_policy" "ci" {
  name = "ci"
  role = "ci-role"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
