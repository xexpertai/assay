resource "aws_security_group" "bastion" {
  name = "bastion"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_instance" "bastion" {
  ami                    = "ami-0abcdef"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.bastion.id]
  user_data              = <<-EOT
    #!/bin/bash
    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  EOT
  metadata_options {
    http_tokens = "required"
  }
}
