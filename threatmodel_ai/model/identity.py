"""Read-only identity migration suggestions for legacy Mermaid element IDs."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from threatmodel_ai.model.schema import Edge, Node, SourceType, SystemModel


@dataclass(frozen=True)
class PossibleIdentityMember:
    """One still-distinct node with compact, non-absolute source hints."""

    id: str
    type: str
    source_hints: tuple[str, ...]


@dataclass(frozen=True)
class PossibleIdentityGroup:
    """A review-only same-name candidate group; never an accepted alias."""

    name: str
    members: tuple[PossibleIdentityMember, ...]

    @property
    def ambiguous(self) -> bool:
        """More than two candidates cannot identify one unique pair."""

        return len(self.members) > 2


def find_possible_identities(model: SystemModel) -> list[PossibleIdentityGroup]:
    """Surface cross-document same-name nodes without changing graph identity."""

    by_name: dict[str, list[Node]] = defaultdict(list)
    for node in model.nodes:
        normalized_name = " ".join(node.name.split()).casefold()
        if normalized_name and normalized_name != "unknown" and _source_keys(node):
            by_name[normalized_name].append(node)

    groups: list[PossibleIdentityGroup] = []
    for nodes in by_name.values():
        source_keys = set().union(*(_source_keys(node) for node in nodes))
        if len(nodes) < 2 or len(source_keys) < 2:
            continue
        ordered = sorted(nodes, key=lambda node: node.id)
        groups.append(
            PossibleIdentityGroup(
                name=min(node.name for node in nodes),
                members=tuple(
                    PossibleIdentityMember(
                        id=node.id,
                        type=node.type.value,
                        source_hints=_source_hints(node),
                    )
                    for node in ordered
                ),
            )
        )
    return sorted(groups, key=lambda group: (group.name.casefold(), group.members[0].id))


def _source_keys(node: Node) -> set[str]:
    """Ignore synthetic pointers when deciding whether sources are distinct."""

    return {
        item.source_path
        for item in node.evidence
        if item.source_type != SourceType.DERIVED and item.source_path != "derived"
    }


def _source_hints(node: Node) -> tuple[str, ...]:
    """Show source type, basename, and line without exposing an operator home path."""

    return tuple(
        sorted(
            {
                f"{item.source_type.value}:{Path(item.source_path).name}"
                + (f":{item.line}" if item.line else "")
                for item in node.evidence
                if item.source_type != SourceType.DERIVED and item.source_path != "derived"
            }
        )
    )


class IdentitySuggestion(BaseModel):
    """A unique old-to-current ID candidate requiring explicit reviewer acceptance."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["node", "edge"]
    legacy_id: str
    current_id: str


class AmbiguousIdentity(BaseModel):
    """One legacy ID with multiple plausible current elements."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["node", "edge"]
    legacy_id: str
    current_ids: list[str]


class IdentityPreview(BaseModel):
    """Non-authoritative migration preview; no model or reviewer state is mutated."""

    model_config = ConfigDict(extra="forbid")

    suggestions: list[IdentitySuggestion]
    ambiguous: list[AmbiguousIdentity]


def preview_legacy_mermaid_identities(legacy: SystemModel, current: SystemModel) -> IdentityPreview:
    """Suggest only unique, kind-preserving mappings from legacy Mermaid IDs."""

    suggestions: list[IdentitySuggestion] = []
    ambiguous: list[AmbiguousIdentity] = []
    for kind, old_elements, new_elements in (
        ("node", legacy.nodes, current.nodes),
        ("edge", legacy.edges, current.edges),
    ):
        old_ids = {element.id for element in old_elements}
        candidates: dict[str, set[str]] = defaultdict(set)
        for element in new_elements:
            legacy_id = _legacy_mermaid_id(element)
            if legacy_id in old_ids and legacy_id != element.id:
                candidates[legacy_id].add(element.id)
        for legacy_id, current_ids in sorted(candidates.items()):
            if len(current_ids) == 1:
                suggestions.append(
                    IdentitySuggestion(
                        kind=kind,
                        legacy_id=legacy_id,
                        current_id=next(iter(current_ids)),
                    )
                )
            else:
                ambiguous.append(
                    AmbiguousIdentity(
                        kind=kind,
                        legacy_id=legacy_id,
                        current_ids=sorted(current_ids),
                    )
                )
    return IdentityPreview(
        suggestions=sorted(suggestions, key=lambda item: (item.kind, item.legacy_id)),
        ambiguous=sorted(ambiguous, key=lambda item: (item.kind, item.legacy_id)),
    )


def _legacy_mermaid_id(element: Node | Edge) -> str | None:
    value = element.metadata.get("legacy_mermaid_id_suggestion")
    return value if isinstance(value, str) and value else None
