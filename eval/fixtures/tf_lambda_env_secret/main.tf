resource "aws_lambda_function" "notify" {
  function_name = "notify"
  role          = "arn:aws:iam::123456789012:role/notify"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  environment {
    variables = {
      SLACK_WEBHOOK_TOKEN = "T9fK2pQ7vLx8Rz3mN4bW"
      STAGE               = "prod"
    }
  }
}
