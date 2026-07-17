"""README extractor using conservative, deterministic Markdown heuristics."""

from __future__ import annotations

import re
from pathlib import Path

from threatmodel_ai.model.ids import make_id
from threatmodel_ai.model.schema import Evidence, Node, NodeType, SourceType, SystemModel, Unknown

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_BULLET_RE = re.compile(r"^\s*[-*]\s+(.+?)\s*$")

_SECTION_TYPES: dict[str, NodeType] = {
    "actors": NodeType.ACTOR,
    "users": NodeType.ACTOR,
    "components": NodeType.COMPONENT,
    "services": NodeType.COMPONENT,
    "apis": NodeType.API,
    "api": NodeType.API,
    "databases": NodeType.DATABASE,
    "data stores": NodeType.DATABASE,
    "external services": NodeType.EXTERNAL_SERVICE,
    "third party services": NodeType.EXTERNAL_SERVICE,
    "secrets": NodeType.SECRET,
    "data assets": NodeType.DATA_ASSET,
    "trust boundaries": NodeType.TRUST_BOUNDARY,
}


def extract_readme(path: Path) -> SystemModel:
    """Extract explicitly documented architecture facts from a README file."""

    text = path.read_text(encoding="utf-8")
    evidence = Evidence(source_type=SourceType.README, source_path=str(path), detail="README")
    title = _first_heading(text) or "unknown"
    description = _first_paragraph(text) or "unknown"
    nodes: dict[str, Node] = {}

    if title != "unknown":
        system_node_id = make_id("component", "readme", title)
        nodes[system_node_id] = Node(
            id=system_node_id,
            name=title,
            type=NodeType.COMPONENT,
            description=description,
            evidence=[evidence],
        )
    else:
        system_node_id = None

    current_type: NodeType | None = None
    current_heading = "README"
    for line in text.splitlines():
        heading_match = _HEADING_RE.match(line)
        if heading_match:
            current_heading = heading_match.group(2).strip()
            current_type = _SECTION_TYPES.get(_normalise_heading(current_heading))
            continue

        bullet_match = _BULLET_RE.match(line)
        if current_type and bullet_match:
            label = _clean_list_item_name(bullet_match.group(1))
            if not label:
                continue
            node_id = make_id(current_type.value, "readme", label)
            nodes.setdefault(
                node_id,
                Node(
                    id=node_id,
                    name=label,
                    type=current_type,
                    description=bullet_match.group(1).strip(),
                    evidence=[
                        Evidence(
                            source_type=SourceType.README,
                            source_path=str(path),
                            detail=f"README section: {current_heading}",
                        )
                    ],
                ),
            )

    metadata = {
        "readme_path": str(path),
        "mentions_authentication": _mentions(text, "authentication", "authn", "login", "oauth"),
        "mentions_authorization": _mentions(text, "authorization", "authz", "permission", "role"),
        "mentions_logging": _mentions(text, "logging", "audit log", "audit trail"),
        "mentions_monitoring": _mentions(text, "monitoring", "alerting", "observability"),
        "mentions_rate_limiting": _mentions(text, "rate limit", "throttle", "quota"),
        "mentions_encryption": _mentions(text, "encryption", "tls", "https", "encrypted"),
    }

    unknowns = _readme_unknowns(path, metadata, system_node_id)
    return SystemModel(
        name=title,
        description=description,
        nodes=sorted(nodes.values(), key=lambda node: (node.type.value, node.id)),
        unknowns=unknowns,
        metadata=metadata,
    )


def _first_heading(text: str) -> str | None:
    for line in text.splitlines():
        match = _HEADING_RE.match(line)
        if match and match.group(1) == "#":
            return match.group(2).strip()
    return None


def _first_paragraph(text: str) -> str | None:
    in_code_block = False
    paragraph: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block or not stripped:
            if paragraph:
                break
            continue
        if stripped.startswith("#") or stripped.startswith(("-", "*", "`")):
            continue
        paragraph.append(stripped)
    return " ".join(paragraph) if paragraph else None


def _normalise_heading(value: str) -> str:
    value = re.sub(r"[^a-z0-9 ]+", " ", value.lower())
    return re.sub(r"\s+", " ", value).strip()


def _clean_list_item_name(value: str) -> str:
    value = re.sub(r"`([^`]+)`", r"\1", value)
    value = value.split(":", 1)[0]
    value = re.split(r"\s+-\s+", value, maxsplit=1)[0]
    return value.strip(" .")


def _mentions(text: str, *needles: str) -> bool:
    lowered = text.lower()
    return any(needle in lowered for needle in needles)


def _readme_unknowns(
    path: Path,
    metadata: dict[str, object],
    related_element_id: str | None,
) -> list[Unknown]:
    unknowns: list[Unknown] = []
    checks = {
        "authentication": "Authentication behavior is not described in the README.",
        "authorization": "Authorization behavior is not described in the README.",
        "logging": "Logging or audit behavior is not described in the README.",
        "monitoring": "Monitoring behavior is not described in the README.",
        "rate_limiting": "Rate limiting behavior is not described in the README.",
        "encryption": "Transport or storage encryption is not described in the README.",
    }
    evidence = Evidence(source_type=SourceType.README, source_path=str(path), detail="README")

    for category, description in checks.items():
        metadata_key = f"mentions_{category}"
        if not metadata.get(metadata_key):
            unknowns.append(
                Unknown(
                    id=make_id("unknown", "readme", category),
                    category=category,
                    description=description,
                    related_element_id=related_element_id,
                    evidence=evidence,
                )
            )
    return unknowns
