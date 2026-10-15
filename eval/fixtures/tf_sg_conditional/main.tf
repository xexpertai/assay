variable "world" { default = false }
resource "aws_security_group" "db" {
  name = "db"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = var.world ? ["0.0.0.0/0"] : ["10.0.0.0/8"]
  }
}
