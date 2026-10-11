resource "aws_instance" "worker" {
  ami           = "ami-123456"
  instance_type = "t3.micro"
  user_data     = <<-EOT
    #!/bin/bash
    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    /opt/worker/start.sh
  EOT
}
