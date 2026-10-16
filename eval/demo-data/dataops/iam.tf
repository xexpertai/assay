# fictional account 123456789012 (AWS documentation example)
resource "aws_iam_user" "alice" { name = "alice" }
resource "aws_iam_user_policy" "alice_admin" {
  name   = "alice-admin"
  user   = aws_iam_user.alice.name
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}
