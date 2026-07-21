from threatmodel_ai.dfd import render_mermaid
from threatmodel_ai.model.schema import Edge, EdgeType, Node, NodeType, SystemModel


def test_mermaid_generation_is_deterministic() -> None:
    model = SystemModel(
        name="Orders",
        nodes=[
            Node(id="actor:user", name="User", type=NodeType.ACTOR),
            Node(id="api:orders", name="Orders API", type=NodeType.API),
        ],
        edges=[
            Edge(
                id="edge:actor:user:api:orders",
                source="actor:user",
                target="api:orders",
                type=EdgeType.COMMUNICATES_WITH,
                protocol="HTTPS",
            )
        ],
    )

    assert render_mermaid(model) == (
        "flowchart LR\n"
        "  %% Generated from system_model.json. Do not edit manually.\n"
        '  n_b2aa054949(["User\\n(actor)"])\n'
        '  n_2968d039ea["Orders API\\n(api)"]\n'
        '  n_b2aa054949 -->|"communicates_with / HTTPS"| n_2968d039ea\n'
    )


def test_mermaid_generation_renders_trust_boundaries_as_subgraphs() -> None:
    model = SystemModel(
        name="Orders",
        nodes=[
            Node(id="actor:user", name="User", type=NodeType.ACTOR),
            Node(
                id="boundary:private",
                name="Private Zone",
                type=NodeType.TRUST_BOUNDARY,
            ),
            Node(
                id="api:orders",
                name="Orders API",
                type=NodeType.API,
                trust_boundary_id="boundary:private",
            ),
        ],
        edges=[
            Edge(
                id="edge:actor:user:api:orders",
                source="actor:user",
                target="api:orders",
                type=EdgeType.COMMUNICATES_WITH,
            )
        ],
    )

    rendered = render_mermaid(model)

    assert 'subgraph n_b654fb8f3e["Private Zone\\n(trust_boundary)"]' in rendered
    assert 'n_2968d039ea["Orders API\\n(api)"]' in rendered
    assert 'n_b2aa054949 -->|"communicates_with"| n_2968d039ea' in rendered
