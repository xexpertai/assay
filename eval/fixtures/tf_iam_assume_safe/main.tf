resource "aws_iam_role" "deploy" {
  name = "deploy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = { "token.actions.githubusercontent.com:sub" = "repo:acme/app:ref:refs/heads/main" } }
    }]
  })
}
