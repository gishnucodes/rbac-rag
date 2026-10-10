"""Heading-aware Markdown chunker with section-level ACL directives.

A section can change its ACL with an HTML comment placed anywhere in the
section body (conventionally right under the heading)::

    ## Break-glass procedure
    <!-- acl: allow=role:sre,user:alice deny=group:contractors mode=replace classification=confidential -->

The directive applies to the section and all of its subsections. ``mode`` is
``extend`` (default: add to the inherited ACL) or ``replace`` (replace the
inherited allows; inherited denies always remain). Chunks never span two
sections, so every chunk has exactly one ACL.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from rbac_rag.chunking.recursive import split_text
from rbac_rag.types import Acl, AclOverride, ChunkDraft, SourceDocument

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_DIRECTIVE_RE = re.compile(r"<!--\s*acl:(.*?)-->", re.DOTALL)
_FENCE_RE = re.compile(r"^(```|~~~)")


def parse_acl_directive(body: str) -> AclOverride:
    allow: list[str] = []
    deny: list[str] = []
    mode = "extend"
    classification: str | None = None
    for token in body.split():
        key, sep, value = token.partition("=")
        if not sep:
            raise ValueError(f"malformed ACL directive token {token!r}")
        values = [v for v in value.split(",") if v]
        if key == "allow":
            allow.extend(values)
        elif key == "deny":
            deny.extend(values)
        elif key == "mode":
            mode = value
        elif key == "classification":
            classification = value
        else:
            raise ValueError(f"unknown ACL directive key {key!r}")
    if mode not in ("extend", "replace"):
        raise ValueError(f"ACL directive mode must be 'extend' or 'replace', got {mode!r}")
    return AclOverride(Acl.from_specs(allow, deny), mode=mode, classification=classification)


@dataclass
class _Section:
    level: int
    path: tuple[str, ...]
    lines: list[str]
    override: AclOverride | None = None


def _combine(parent: AclOverride | None, child: AclOverride | None) -> AclOverride | None:
    """Compose a parent section's override with a child's."""
    if parent is None or child is None:
        return child or parent
    if child.mode == "replace":
        acl = Acl(child.acl.allow, parent.acl.deny | child.acl.deny)
        mode = "replace"
    else:
        acl = Acl(parent.acl.allow | child.acl.allow, parent.acl.deny | child.acl.deny)
        mode = parent.mode
    return AclOverride(acl, mode=mode, classification=child.classification or parent.classification)


class MarkdownChunker:
    def __init__(self, chunk_size: int = 800, chunk_overlap: int = 120):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def _sections(self, text: str) -> list[_Section]:
        sections = [_Section(level=0, path=(), lines=[])]
        stack: list[_Section] = [sections[0]]
        in_fence = False
        for line in text.splitlines():
            if _FENCE_RE.match(line.strip()):
                in_fence = not in_fence
            match = None if in_fence else _HEADING_RE.match(line)
            if match:
                level = len(match.group(1))
                while stack[-1].level >= level:
                    stack.pop()
                section = _Section(level, stack[-1].path + (match.group(2),), [])
                stack.append(section)
                sections.append(section)
            else:
                stack[-1].lines.append(line)
        return sections

    def split(self, document: SourceDocument) -> list[ChunkDraft]:
        sections = self._sections(document.text)
        # Resolve directives, inheriting from the nearest enclosing section.
        resolved: list[tuple[_Section, AclOverride | None, str]] = []
        enclosing: list[tuple[int, AclOverride | None]] = []
        for section in sections:
            body = "\n".join(section.lines)
            own: AclOverride | None = None
            for match in _DIRECTIVE_RE.finditer(body):
                own = _combine(own, parse_acl_directive(match.group(1)))
            body = _DIRECTIVE_RE.sub("", body)
            while enclosing and enclosing[-1][0] >= section.level:
                enclosing.pop()
            parent = enclosing[-1][1] if enclosing else None
            effective = _combine(parent, own)
            enclosing.append((section.level, effective))
            resolved.append((section, effective, body))

        drafts: list[ChunkDraft] = []
        for section, override, body in resolved:
            if not body.strip():
                continue
            breadcrumb = " > ".join((document.title, *section.path))
            budget = max(self.chunk_size - len(breadcrumb) - 1, self.chunk_size // 2)
            for piece in split_text(body, budget, min(self.chunk_overlap, budget - 1)):
                drafts.append(
                    ChunkDraft(
                        content=f"{breadcrumb}\n{piece}",
                        metadata={"section": list(section.path)},
                        override=override,
                    )
                )
        return drafts
