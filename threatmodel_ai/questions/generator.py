"""Generate review questions from unknown model facts and security gaps."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from threatmodel_ai.model.ids import make_id
from threatmodel_ai.model.schema import Edge, Node, NodeType, SystemModel, Unknown


class Question(BaseModel):
    """A security review question derived from an unknown or deterministic rule."""

    model_config = ConfigDict(extra="forbid")

    id: str
    category: str
    question: str
    rationale: str
    related_elements: list[str] = Field(default_factory=list)


def generate_questions(model: SystemModel) -> list[Question]:
    """Generate deterministic clarification questions from a system model."""

    node_by_id = {node.id: node for node in model.nodes}
    questions: dict[str, Question] = {}

    for unknown in model.unknowns:
        question = _question_from_unknown(unknown, node_by_id)
        questions.setdefault(question.id, question)

    for edge in model.edges:
        source = node_by_id.get(edge.source)
        target = node_by_id.get(edge.target)
        if not source or not target:
            continue
        for question in _questions_for_edge(edge, source, target, model):
            questions.setdefault(question.id, question)

    for node in model.nodes:
        for question in _questions_for_node(node):
            questions.setdefault(question.id, question)

    return sorted(questions.values(), key=lambda item: (item.category, item.id))


def _question_from_unknown(unknown: Unknown, node_by_id: dict[str, Node]) -> Question:
    related_name = None
    if unknown.related_element_id and unknown.related_element_id in node_by_id:
        related_name = node_by_id[unknown.related_element_id].name
    question_text = _unknown_question_text(unknown, related_name)
    return Question(
        id=make_id("question", unknown.id),
        category=unknown.category,
        question=question_text,
        rationale=unknown.description,
        related_elements=[unknown.related_element_id] if unknown.related_element_id else [],
    )


def _unknown_question_text(unknown: Unknown, related_name: str | None) -> str:
    target = f" for {related_name}" if related_name else ""
    match unknown.category:
        case "authentication":
            return f"How is authentication implemented{target}?"
        case "authorization":
            return f"What authorization rules are enforced{target}?"
        case "data_classification":
            return f"What is the data classification{target}?"
        case "logging":
            return f"What security-relevant events are logged{target}?"
        case "monitoring":
            return f"What monitoring and alerting exists{target}?"
        case "rate_limiting":
            return f"What rate limits or abuse controls are enforced{target}?"
        case "encryption":
            return f"What encryption is used in transit and at rest{target}?"
        case _:
            return f"What is the missing {unknown.category.replace('_', ' ')} detail{target}?"


def _questions_for_edge(
    edge: Edge,
    source: Node,
    target: Node,
    model: SystemModel,
) -> list[Question]:
    questions: list[Question] = []
    is_external_entry = source.type == NodeType.ACTOR and target.type in {
        NodeType.API,
        NodeType.COMPONENT,
        NodeType.EXTERNAL_SERVICE,
    }
    if not is_external_entry:
        return questions

    if edge.authentication == "unknown":
        questions.append(
            _edge_question(
                edge,
                "authentication",
                f"How is {target.name} authenticated when called by {source.name}?",
                "Authentication is unknown for this external entry point.",
            )
        )
    elif edge.authentication == "none":
        questions.append(
            _edge_question(
                edge,
                "authentication",
                f"Is unauthenticated access to {target.name} intentional?",
                "The model indicates this entry point has no authentication requirement.",
            )
        )
    if edge.authorization == "unknown":
        questions.append(
            _edge_question(
                edge,
                "authorization",
                f"What authorization checks protect {target.name}?",
                "Authorization is unknown for this external entry point.",
            )
        )
    if edge.protocol in {"unknown", "HTTP"}:
        questions.append(
            _edge_question(
                edge,
                "encryption",
                f"Is traffic from {source.name} to {target.name} protected with TLS?",
                "Transport protection is not proven by the model.",
            )
        )
    if not model.metadata.get("mentions_rate_limiting"):
        questions.append(
            _edge_question(
                edge,
                "rate_limiting",
                f"What rate limits protect {target.name}?",
                "Rate limiting is not proven for this external entry point.",
            )
        )
    if not (model.metadata.get("mentions_logging") or model.metadata.get("mentions_monitoring")):
        questions.append(
            _edge_question(
                edge,
                "logging_monitoring",
                f"What logging and monitoring exists for {target.name}?",
                "Audit logging and monitoring are not proven for this external entry point.",
            )
        )
    return questions


def _questions_for_node(node: Node) -> list[Question]:
    questions: list[Question] = []
    if node.type == NodeType.DATA_ASSET and "classification" not in node.metadata:
        questions.append(
            Question(
                id=make_id("question", node.id, "data-classification"),
                category="data_classification",
                question=f"What is the data classification for {node.name}?",
                rationale="Data asset classification is not present in the model.",
                related_elements=[node.id],
            )
        )
    if node.type in {NodeType.DATABASE, NodeType.DATA_ASSET, NodeType.SECRET}:
        questions.append(
            Question(
                id=make_id("question", node.id, "encryption"),
                category="encryption",
                question=f"What encryption and access controls protect {node.name}?",
                rationale="Storage protection details are not present in the model.",
                related_elements=[node.id],
            )
        )
    return questions


def _edge_question(edge: Edge, category: str, question: str, rationale: str) -> Question:
    return Question(
        id=make_id("question", edge.id, category),
        category=category,
        question=question,
        rationale=rationale,
        related_elements=[edge.id, edge.source, edge.target],
    )
