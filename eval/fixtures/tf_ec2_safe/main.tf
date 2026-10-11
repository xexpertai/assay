resource "aws_instance" "app" {
  ami                  = "ami-123456"
  instance_type        = "t3.micro"
  iam_instance_profile = "app-profile"
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  user_data = <<EOT
#!/bin/bash
aws ssm get-parameter --name /app/db-password --with-decryption > /dev/null
EOT
}
