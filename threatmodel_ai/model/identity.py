"""Read-only identity migration suggestions for legacy Mermaid element IDs."""

from __future__ import annotations

from collections import defaultdict
from typing import Literal

from pydantic import BaseModel, ConfigDict

from threatmodel_ai.model.schema import Edge, Node, SystemModel


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
