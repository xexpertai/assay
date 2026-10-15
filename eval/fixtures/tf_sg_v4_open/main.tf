resource "aws_security_group" "bastion" {
  name   = "bastion"
  vpc_id = "vpc-0123"
}
resource "aws_vpc_security_group_ingress_rule" "ssh_world" {
  security_group_id = aws_security_group.bastion.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}
resource "aws_vpc_security_group_ingress_rule" "all_v6" {
  security_group_id = aws_security_group.bastion.id
  cidr_ipv6         = "::/0"
  ip_protocol       = "-1"
}
