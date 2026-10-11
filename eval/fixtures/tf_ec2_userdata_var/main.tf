resource "aws_instance" "app" {
  ami           = "ami-123456"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
  }
  user_data = <<EOF2
#!/bin/bash
echo "DB_PASS=${var.db_password}" > /etc/app.env
EOF2
}
