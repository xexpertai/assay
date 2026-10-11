resource "aws_lambda_function" "notify" {
  function_name = "notify"
  role          = "arn:aws:iam::123456789012:role/notify"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  environment {
    variables = {
      TOKEN_SECRET_ARN = aws_secretsmanager_secret.slack.arn
      STAGE            = "prod"
    }
  }
}
