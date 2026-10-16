resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_instance" "web" {
  ami                    = "ami-0abcdef"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web.id]
  metadata_options {
    http_tokens = "optional"
  }
}
