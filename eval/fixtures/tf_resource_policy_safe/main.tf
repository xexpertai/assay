resource "aws_sns_topic" "alerts" {
  name = "alerts"
}
resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = { StringEquals = { "aws:SourceAccount" = "123456789012" } }
    }]
  })
}
resource "aws_kms_key" "data" {
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::123456789012:root" }, Action = "kms:*", Resource = "*" }]
  })
}
