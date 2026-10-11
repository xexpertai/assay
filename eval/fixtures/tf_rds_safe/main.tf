resource "aws_db_instance" "orders" {
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  username                    = "app"
  manage_master_user_password = true
  storage_encrypted           = true
  publicly_accessible         = false
}
resource "aws_rds_cluster" "analytics" {
  engine            = "aurora-postgresql"
  master_username   = "app"
  master_password   = var.analytics_password
  storage_encrypted = true
}
