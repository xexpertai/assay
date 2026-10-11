resource "aws_db_instance" "orders" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  username            = "app"
  password            = "Pg-Orders-2024!x9"
  publicly_accessible = true
}
