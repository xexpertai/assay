resource "aws_db_instance" "main" {
  identifier          = "main"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "app"
  password            = var.db_password
  storage_encrypted   = var.encrypt ? true : false
  publicly_accessible = var.public
}
resource "aws_security_group" "db" {
  name = "db"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.cidr]
  }
}
resource "aws_ebs_volume" "v" {
  availability_zone = "a"
  size              = 1
  encrypted         = !var.encrypt
}
