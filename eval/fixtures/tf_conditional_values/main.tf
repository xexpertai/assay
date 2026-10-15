variable "public" { default = false }
variable "no_encryption" { default = false }
resource "aws_db_instance" "main" {
  identifier          = "main"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "app"
  password            = var.db_password
  storage_encrypted   = var.no_encryption ? false : true
  publicly_accessible = var.public
}
resource "aws_kms_key" "main" {
  enable_key_rotation = !var.no_encryption
}
