module "db" {
  source = "./modules/db"
  public = var.expose_db
}
variable "expose_db" {}
