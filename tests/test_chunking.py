import pytest
from rbac_rag.chunking.markdown import MarkdownChunker, parse_acl_directive
from rbac_rag.chunking.recursive import split_text
from rbac_rag.types import Acl, AclOverride, Principal, PrincipalType, SourceDocument

def test_split_text_bounds_and_overlap():
    text = "Paragraph 1 sentence 1. Paragraph 1 sentence 2.\n\nParagraph 2 sentence 1. Paragraph 2 sentence 2."

    # Size bounds
    chunks = split_text(text, chunk_size=30, overlap=5)
    for c in chunks:
        assert len(c) <= 30

    # Overlap checking
    chunks_with_overlap = split_text(text, chunk_size=50, overlap=15)
    assert len(chunks_with_overlap) > 1

    # Invalid arguments
    with pytest.raises(ValueError, match="chunk_size must be positive"):
        split_text(text, chunk_size=0, overlap=0)

    with pytest.raises(ValueError, match="overlap must be in"):
        split_text(text, chunk_size=50, overlap=50)

    with pytest.raises(ValueError, match="overlap must be in"):
        split_text(text, chunk_size=50, overlap=-1)

    # Empty text
    assert split_text("", chunk_size=100, overlap=10) == []
    assert split_text("   ", chunk_size=100, overlap=10) == []


def test_markdown_chunker_breadcrumbs():
    doc_text = """
# Intro
Welcome to the guide.

## Section 1
Content for section 1.

### Subsection 1.1
Content for subsection 1.1.
"""
    doc = SourceDocument(
        id="doc1",
        title="Guide",
        text=doc_text,
        classification="public",
        acl=Acl(),
    )
    chunker = MarkdownChunker()
    drafts = chunker.split(doc)

    breadcrumbs = [d.content.splitlines()[0] for d in drafts]
    assert "Guide > Intro" in breadcrumbs
    assert "Guide > Intro > Section 1" in breadcrumbs
    assert "Guide > Intro > Section 1 > Subsection 1.1" in breadcrumbs


def test_markdown_chunker_section_directives_extend_vs_replace():
    doc_text = """
# Section Extend
<!-- acl: allow=role:eng mode=extend -->
Extend body.

# Section Replace
<!-- acl: allow=role:admin mode=replace -->
Replace body.
"""
    base_acl = Acl.from_specs(allow=["role:viewer"], deny=["user:bad_actor"])
    doc = SourceDocument(
        id="doc1",
        title="Doc",
        text=doc_text,
        classification="internal",
        acl=base_acl,
    )
    chunker = MarkdownChunker()
    drafts = chunker.split(doc)

    assert len(drafts) == 2

    # First section (extend)
    acl1 = drafts[0].override.apply(base_acl)
    assert Principal(PrincipalType.ROLE, "viewer") in acl1.allow
    assert Principal(PrincipalType.ROLE, "eng") in acl1.allow
    assert Principal(PrincipalType.USER, "bad_actor") in acl1.deny

    # Second section (replace)
    acl2 = drafts[1].override.apply(base_acl)
    assert Principal(PrincipalType.ROLE, "admin") in acl2.allow
    assert Principal(PrincipalType.ROLE, "viewer") not in acl2.allow
    assert Principal(PrincipalType.USER, "bad_actor") in acl2.deny


def test_markdown_chunker_nested_sections_inherit_and_preserve_denies():
    doc_text = """
# Parent
<!-- acl: allow=role:parent_allow deny=user:parent_deny mode=extend classification=confidential -->
Parent body.

## Child Replace
<!-- acl: allow=role:child_allow mode=replace -->
Child replace body.

## Child Extend
<!-- acl: allow=role:child_extend mode=extend -->
Child extend body.
"""
    doc = SourceDocument(
        id="doc1",
        title="Doc",
        text=doc_text,
        classification="public",
        acl=Acl(),
    )
    chunker = MarkdownChunker()
    drafts = chunker.split(doc)

    # Parent draft
    parent_override = drafts[0].override
    assert parent_override.classification == "confidential"

    # Child Replace draft
    child_replace_override = drafts[1].override
    # Effective parent override had allow={parent_allow}, deny={parent_deny}
    # Child replace override replaces parent allows, but MUST preserve parent denies
    assert child_replace_override.classification == "confidential"
    applied = child_replace_override.apply(Acl())
    assert Principal(PrincipalType.ROLE, "child_allow") in applied.allow
    assert Principal(PrincipalType.ROLE, "parent_allow") not in applied.allow
    assert Principal(PrincipalType.USER, "parent_deny") in applied.deny

    # Child Extend draft
    child_extend_override = drafts[2].override
    assert child_extend_override.classification == "confidential"
    applied_ext = child_extend_override.apply(Acl())
    assert Principal(PrincipalType.ROLE, "parent_allow") in applied_ext.allow
    assert Principal(PrincipalType.ROLE, "child_extend") in applied_ext.allow
    assert Principal(PrincipalType.USER, "parent_deny") in applied_ext.deny


def test_markdown_chunker_classification_override():
    doc_text = """
# Section 1
<!-- acl: classification=restricted -->
Restricted text.
"""
    doc = SourceDocument(
        id="doc1",
        title="Doc",
        text=doc_text,
        classification="public",
        acl=Acl(),
    )
    chunker = MarkdownChunker()
    drafts = chunker.split(doc)
    assert drafts[0].override.classification == "restricted"


def test_markdown_chunker_fenced_code_blocks_ignored():
    doc_text = """
# Real Heading

```markdown
# Code Heading
## Another Code Heading
```

Real content.
"""
    doc = SourceDocument(
        id="doc1",
        title="Doc",
        text=doc_text,
        classification="public",
        acl=Acl(),
    )
    chunker = MarkdownChunker()
    drafts = chunker.split(doc)

    # Heading inside fenced code block should not create new sections
    sections = [d.metadata["section"] for d in drafts]
    assert len(sections) == 1
    assert sections[0] == ["Real Heading"]
    assert "# Code Heading" in drafts[0].content


def test_markdown_chunker_malformed_directives():
    with pytest.raises(ValueError, match="malformed ACL directive token"):
        parse_acl_directive("invalid_token_no_equals")

    with pytest.raises(ValueError, match="unknown ACL directive key"):
        parse_acl_directive("foo=bar")

    with pytest.raises(ValueError, match="ACL directive mode must be"):
        parse_acl_directive("mode=invalid")
