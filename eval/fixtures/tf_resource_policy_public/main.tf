resource "aws_sqs_queue" "events" {
  name = "events"
}
resource "aws_sqs_queue_policy" "events" {
  queue_url = aws_sqs_queue.events.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = "*", Action = "sqs:*", Resource = aws_sqs_queue.events.arn }]
  })
}
resource "aws_kms_key" "data" {
  enable_key_rotation = true
  policy = <<-POLICY
  {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "kms:*", "Resource": "*"}
  ]}
  POLICY
}
