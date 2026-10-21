resource "aws_security_group_rule" "ssh" {
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["0.0.0.0/0"]
}
