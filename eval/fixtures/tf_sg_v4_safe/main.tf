resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = "vpc-0123"
}
resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.web.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}
resource "aws_vpc_security_group_ingress_rule" "ssh_office" {
  security_group_id = aws_security_group.web.id
  cidr_ipv4         = "203.0.113.0/24"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}
