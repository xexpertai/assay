"""A small, dependency-free Terraform (HCL2) structure parser.

It understands blocks, attributes, strings with ${...} interpolation, heredocs and the
three comment styles. Attribute values are kept as raw expression text: the rules only
need literal checks such as `encrypted = true` or `cidr_blocks = ["0.0.0.0/0"]`.
Comments are dropped, so annotations in sample repos can never influence a finding.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*")
HEREDOC_RE = re.compile(r"<<-?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\n")


@dataclass
class Attr:
    value: str
    line: int


@dataclass
class Block:
    type: str
    labels: list[str]
    line: int
    attrs: dict[str, Attr] = field(default_factory=dict)
    blocks: list["Block"] = field(default_factory=list)

    def children(self, type_: str) -> list["Block"]:
        return [b for b in self.blocks if b.type == type_]

    def get(self, name: str) -> str | None:
        a = self.attrs.get(name)
        return a.value if a else None

    @property
    def address(self) -> str:
        if self.type in ("resource", "data") and len(self.labels) == 2:
            prefix = "data." if self.type == "data" else ""
            return f"{prefix}{self.labels[0]}.{self.labels[1]}"
        return ".".join([self.type, *self.labels])


class _Parser:
    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.n = len(text)

    def line(self, pos: int | None = None) -> int:
        return self.s.count("\n", 0, self.i if pos is None else pos) + 1

    def peek(self, k: int = 0) -> str:
        j = self.i + k
        return self.s[j] if j < self.n else ""

    def skip_ws(self, newlines: bool = True) -> None:
        while self.i < self.n:
            c = self.s[self.i]
            if c in " \t\r" or (newlines and c == "\n"):
                self.i += 1
            elif c == "#" or (c == "/" and self.peek(1) == "/"):
                while self.i < self.n and self.s[self.i] != "\n":
                    self.i += 1
            elif c == "/" and self.peek(1) == "*":
                end = self.s.find("*/", self.i + 2)
                self.i = self.n if end < 0 else end + 2
            else:
                break

    def read_string(self) -> str:
        """Read a quoted string starting at the opening quote; return it with quotes."""
        start = self.i
        self.i += 1
        depth = 0
        while self.i < self.n:
            c = self.s[self.i]
            if c == "\\":
                self.i += 2
                continue
            if c == "$" and self.peek(1) == "{":
                depth += 1
                self.i += 2
                continue
            if depth and c == "}":
                depth -= 1
            elif depth and c == '"':
                self.read_string()
                continue
            elif not depth and c == '"':
                self.i += 1
                return self.s[start:self.i]
            elif c == "\n" and not depth:
                break  # unterminated string: stop at end of line
            self.i += 1
        return self.s[start:self.i]

    def read_expr(self) -> str:
        out: list[str] = []
        depth = 0
        while self.i < self.n:
            c = self.s[self.i]
            if c == '"':
                out.append(self.read_string())
                continue
            if c == "<" and self.peek(1) == "<":
                m = HEREDOC_RE.match(self.s, self.i)
                if m:
                    tag = m.group(1)
                    body_start = m.end()
                    end_re = re.compile(rf"^[ \t]*{re.escape(tag)}[ \t]*$", re.M)
                    em = end_re.search(self.s, body_start)
                    end = em.end() if em else self.n
                    out.append(self.s[self.i:end])
                    self.i = end
                    continue
            if c == "#" or (c == "/" and self.peek(1) in "/*"):
                self.skip_ws(newlines=False)
                continue
            if c in "{[(":
                depth += 1
            elif c in "}])":
                if depth == 0:
                    break
                depth -= 1
            elif c == "\n" and depth == 0:
                break
            out.append(c)
            self.i += 1
        return "".join(out).strip()

    def parse_body(self, top: bool) -> tuple[dict[str, Attr], list[Block]]:
        attrs: dict[str, Attr] = {}
        blocks: list[Block] = []
        while True:
            self.skip_ws()
            if self.i >= self.n:
                return attrs, blocks
            if self.s[self.i] == "}":
                if not top:
                    self.i += 1
                    return attrs, blocks
                self.i += 1
                continue
            m = IDENT_RE.match(self.s, self.i)
            if not m:
                # unknown token: skip one line to stay robust
                nl = self.s.find("\n", self.i)
                self.i = self.n if nl < 0 else nl + 1
                continue
            name = m.group(0)
            start_line = self.line()
            self.i = m.end()
            self.skip_ws(newlines=False)
            if self.peek() == "=" and self.peek(1) != "=":
                self.i += 1
                self.skip_ws(newlines=False)
                attrs[name] = Attr(self.read_expr(), start_line)
                continue
            labels: list[str] = []
            while self.i < self.n and self.peek() != "{":
                self.skip_ws(newlines=False)
                if self.peek() == '"':
                    labels.append(self.read_string()[1:-1])
                else:
                    lm = IDENT_RE.match(self.s, self.i)
                    if not lm:
                        break
                    labels.append(lm.group(0))
                    self.i = lm.end()
                self.skip_ws(newlines=False)
            if self.peek() != "{":
                nl = self.s.find("\n", self.i)
                self.i = self.n if nl < 0 else nl + 1
                continue
            self.i += 1
            a, b = self.parse_body(top=False)
            blocks.append(Block(name, labels, start_line, a, b))


def parse(text: str) -> list[Block]:
    """Parse Terraform source into top-level blocks."""
    _, blocks = _Parser(text).parse_body(top=True)
    return blocks


def unquote(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def is_true(value: str | None) -> bool:
    return value is not None and unquote(value).lower() == "true"


def is_false(value: str | None) -> bool:
    return value is not None and unquote(value).lower() == "false"


REF_RE = re.compile(r"\b((?:data\.)?[a-z][a-z0-9_]*\.[A-Za-z_][A-Za-z0-9_\-]*)(?:\[[^\]]*\])?\.(?:id|arn|name|bucket|json)\b")


def references(block: Block) -> set[str]:
    """Addresses of other resources this block refers to (e.g. aws_security_group.web)."""
    refs: set[str] = set()

    def walk(b: Block) -> None:
        for a in b.attrs.values():
            refs.update(REF_RE.findall(a.value))
        for c in b.blocks:
            walk(c)

    walk(block)
    refs.discard(block.address)
    return {r for r in refs if not r.startswith(("var.", "local.", "module."))}
