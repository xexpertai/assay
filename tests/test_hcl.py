from assay.hcl import parse, references

SRC = '''
# comment with resource "fake" "x" {
resource "aws_instance" "web" {
  ami = "ami-1" // trailing
  vpc_security_group_ids = [aws_security_group.web.id]
  user_data = <<-EOT
    echo "${var.name}" # not a comment inside heredoc
  EOT
  /* block
     comment */
  metadata_options {
    http_tokens = "required"
  }
}
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''


def test_blocks_and_attrs():
    blocks = parse(SRC)
    assert [b.address for b in blocks] == ["aws_instance.web", "aws_security_group.web"]
    web = blocks[0]
    assert web.get("ami") == '"ami-1"'
    assert "not a comment inside heredoc" in web.get("user_data")
    assert web.children("metadata_options")[0].get("http_tokens") == '"required"'
    assert web.attrs["ami"].line == 4


def test_comments_are_ignored():
    assert all(b.labels != ["fake", "x"] for b in parse(SRC))


def test_references():
    assert references(parse(SRC)[0]) == {"aws_security_group.web"}
