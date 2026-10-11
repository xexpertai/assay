resource "aws_eks_cluster" "main" {
  name     = "main"
  role_arn = "arn:aws:iam::123456789012:role/eks"
  vpc_config {
    subnet_ids = ["subnet-1", "subnet-2"]
  }
}
