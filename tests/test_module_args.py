"""Judge R3 fix 7: literal module-call arguments (one level) feed the called module's variables."""
from assay.agent import run

MOD = '''
variable "admin_cidr" { default = "10.1.0.0/16" }
resource "aws_security_group" "rdp" {
  name = "rdp"
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
}
'''


def _tree(tmp_path, calls):
    (tmp_path / "net").mkdir()
    (tmp_path / "net" / "main.tf").write_text(MOD)
    (tmp_path / "main.tf").write_text(calls)
    return run(str(tmp_path))


def test_caller_literal_reaches_the_module_and_shows_its_source(tmp_path):
    res = _tree(tmp_path, 'module "net" {\n  source = "./net"\n  admin_cidr = "0.0.0.0/0"\n}\n')
    f = [x for x in res.findings if x.rule_id == "TF-AWS-SG-OPEN-ADMIN"]
    assert len(f) == 1 and f[0].file == "net/main.tf" and f[0].confidence == "high"
    assert "argument of module.net in main.tf" in f[0].evidence


def test_caller_safe_literal_is_not_flagged(tmp_path):
    res = _tree(tmp_path, 'module "net" {\n  source = "./net"\n  admin_cidr = "10.9.0.0/16"\n}\n')
    assert not res.findings


def test_unpassed_variable_keeps_its_default(tmp_path):
    res = _tree(tmp_path, 'module "net" {\n  source = "./net"\n}\n')
    assert not res.findings


def test_expression_argument_is_not_trusted_and_is_noted(tmp_path):
    res = _tree(tmp_path, 'variable "c" {}\nmodule "net" {\n  source = "./net"\n  admin_cidr = var.c\n}\n')
    assert not [x for x in res.findings if x.confidence == "high"]
    assert any("comes from the module caller" in d.reason for d in res.decisions if d.stage == "analyse")


def test_two_callers_that_disagree_stay_unresolved(tmp_path):
    res = _tree(tmp_path, 'module "a" {\n  source = "./net"\n  admin_cidr = "0.0.0.0/0"\n}\n'
                          'module "b" {\n  source = "./net"\n  admin_cidr = "10.0.0.0/8"\n}\n')
    assert not [x for x in res.findings if x.confidence == "high"]
    assert any("callers pass different values" in d.reason for d in res.decisions)
