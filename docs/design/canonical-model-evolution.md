# Canonical Model Evolution and Review State

Status: Proposed

Target: `system_model.json` 0.2 and the first Model Diff implementation

Last updated: 2026-08-15

## Purpose

This document turns the P0 Canonical Model roadmap into an implementation design.
It defines:

* the boundary between observations, facts, inferences, unknowns, and security
  assessments;
* backward-compatible evolution from the current 0.1 model;
* stable identities and deterministic fingerprints for Model Diff;
* persistence of threat-review decisions without making workflow state part of
  the architecture source of truth; and
* an incremental delivery order with rollback points.

The design does not add new input formats. It strengthens the canonical model so
future deterministic, generative, and runtime adapters can share one trust model.

## Decisions

1. `system_model.json` remains the source of truth for accepted architecture
   facts, explicit inferences, and unknowns.
2. Extractors emit `ObservationBatch` objects. They do not directly decide what
   becomes an accepted fact.
3. Inferred values remain explicit `Inference` records. A resolved in-memory view
   may apply them, but serialization does not rewrite an inference as a fact.
4. STRIDE, ATT&CK, review priority, and questions remain derived outputs. They are
   not embedded in `system_model.json`.
5. Review decisions are operational state stored in SQLite. The database is not
   an architecture source of truth and does not contain raw source files or the
   complete system model by default.
6. Model readers migrate supported older models in memory. Writers emit only the
   current schema. Migration never overwrites an input file.
7. IDs and fingerprints use semantic inputs. Report wording, evidence ordering,
   timestamps, and absolute output paths cannot determine identity.

## Data Boundaries

```text
Raw artifact
    -> CandidateObservation[]
    -> normalization policy
    -> accepted facts + explicit inferences + unknowns
    -> system_model.json
    -> resolved read-only model view
    -> STRIDE / ATT&CK / review priority / questions
    -> finding candidates
    -> review-state.db
```

`ObservationBatch` is an adapter contract. It may be transient. Persisting it is
an explicit diagnostic option because observations can reveal input locations and
architecture details.

## Semantic Layers

| Layer | Meaning | May be produced by | Stored in |
| --- | --- | --- | --- |
| Observation | A proposed model change with evidence, provenance, and confidence | Any adapter | `ObservationBatch` |
| Fact | An architecture statement explicitly supported by accepted evidence | Normalizer | `system_model.json` |
| Inference | A derived architecture statement with a rule and `based_on` references | Deterministic rule or reviewed proposal | `system_model.json` |
| Unknown | Security-relevant information that cannot be established | Extractor or normalizer | `system_model.json` |
| Assessment | A security conclusion derived from facts or accepted inferences | STRIDE, ATT&CK, risk, or question lens | Generated artifacts |
| Review decision | Human disposition of an assessment | Reviewer | `review-state.db` |

### Fact acceptance

An observation may become a fact only when all of the following are true:

* it has at least one valid Evidence pointer;
* all referenced model elements exist or are accepted in the same normalization
  transaction;
* it does not conflict with an existing fact;
* its provenance is `deterministic`, or it is explicitly marked
  `human_reviewed`; and
* its adapter-specific acceptance rule says the source syntax directly supports
  the proposed meaning.

Confidence alone never promotes a generated observation. A generated observation
must be reviewed and reissued as `human_reviewed` before normalization.

### Fact versus inference examples

| Input | Fact | Inference or assessment |
| --- | --- | --- |
| Terraform contains `aws_lb.public` | The resource exists | It is an internet entry point only when an explicit attribute supports that conclusion |
| OpenAPI declares an `apiKey` security scheme | The scheme is declared | The implementation enforces the scheme |
| Mermaid label contains `Orders DB` | A node named `Orders DB` exists | The node is a database unless the diagram syntax states the type explicitly |
| A public API has no documented authorization | Authorization is unknown | Authorization bypass is a STRIDE candidate, not a fact |

## Target 0.2 Canonical Model

Version 0.2 is additive where possible. Existing node, edge, unknown, and Evidence
fields remain readable.

### New model concepts

The target schema adds:

* `SystemModel.evidence`: provenance for system-level name, description, and
  metadata;
* `SystemModel.inferences`: explicit architecture inferences;
* `NodeType.UNKNOWN`: a non-semantic fallback for nodes whose type is not known;
* `attribute_evidence` on nodes and edges; and
* versioned identity aliases needed for reviewed renames.

Existence evidence and attribute evidence have different meanings:

* `element.evidence` supports the existence of the node or edge;
* `attribute_evidence` supports a specific JSON Pointer such as `/type`,
  `/protocol`, `/trust_boundary_id`, or `/metadata/internet_exposed`.

An attribute with no support must be `unknown`, absent, or represented as an
Inference. Metadata cannot be used to bypass this rule for security-relevant
values.

### Proposed inference shape

```json
{
  "id": "inference:mermaid:orders-db:type",
  "subject_id": "node:mermaid:orders-db",
  "predicate": "/type",
  "value": "database",
  "based_on": [
    {
      "element_id": "node:mermaid:orders-db",
      "path": "/name"
    }
  ],
  "rule_id": "mermaid-label-node-type",
  "confidence": 0.9,
  "provenance_class": "deterministic",
  "evidence": [
    {
      "source_type": "markdown",
      "source_path": "docs/architecture.md",
      "extractor": "mermaid",
      "detail": "mermaid block 1",
      "line": 12
    }
  ]
}
```

`predicate` and `based_on.path` are RFC 6901 JSON Pointers relative to the
referenced model element. Arbitrary executable expressions are not allowed.

### Inference rules

* `subject_id`, every `based_on.element_id`, and every referenced path must exist.
* An inference must have a stable `rule_id`, confidence, provenance, and evidence.
* An inference cannot overwrite a known fact in the resolved view.
* Two inferences proposing different values for the same subject and predicate
  create a conflict Unknown. Confidence does not silently select a winner.
* Generated inferences remain outside the canonical model until human review.
* Deterministic inference rules are versioned and covered by golden fixtures.
* Assessments reference inference IDs through `derived_from`, just as they
  currently reference node and edge IDs.

### Resolved model view

Generators consume a read-only `ResolvedSystemModel` produced from the canonical
model:

1. Copy accepted facts.
2. Apply a non-conflicting inference only where the target value is absent or
   `unknown`.
3. Retain the inference ID in the resolved attribute provenance.
4. Surface conflicts and unresolved values to the question generator.

The resolved view is not written as `system_model.json`. This prevents derived
values from becoming indistinguishable from facts on the next run.

## Evidence and Provenance Validation

Evidence remains a non-sensitive pointer. It must not include source excerpts,
secrets, request bodies, environment values, or complete resource definitions.

Normalization validates:

* evidence is present for every accepted element;
* paths are relative or use the stable source identifier supplied by ingestion;
* line numbers are positive when present;
* attribute Evidence points to a present, non-unknown value;
* derived Evidence identifies the deterministic rule in `detail`; and
* duplicate Evidence is canonicalized before hashing or serialization.

For 0.2, security-relevant attributes include at least:

* node type and trust-boundary membership;
* internet exposure and deployment placement;
* edge protocol, authentication, authorization, and data assets; and
* data classification and modeled controls when those concepts are introduced.

## Schema Versioning and Compatibility

### Version format

`schema_version` uses `MAJOR.MINOR`. Schema changes are independent of the Python
package version.

* MINOR: additive fields, new enum values, or a deterministic migration can
  preserve the previous meaning.
* MAJOR: a migration cannot preserve meaning or required identifiers change.

While the schema is below 1.0, every MINOR change still requires an explicit
migration and golden compatibility tests.

### Reader and writer behavior

* Readers detect `schema_version` before Pydantic validation.
* The current and immediately previous MINOR versions are supported.
* Older supported versions migrate sequentially in memory, then validate against
  the current schema.
* A missing version is treated as invalid; it is never guessed.
* A future or unsupported version fails with the supported range and migration
  command in the error message.
* Writers emit only the current version with deterministic key and list ordering.
* `extra="forbid"` remains enabled so misspelled or future fields are not ignored.

### Migration API and CLI

The implementation will provide:

```python
migrate_system_model(payload: dict[str, object], target_version: str) -> dict[str, object]
```

and:

```bash
tm-ai model validate path/system_model.json
tm-ai model migrate path/system_model.json \
  --to 0.2 \
  --out path/system_model.v0.2.json
```

Migration functions are pure, deterministic, and registered one version step at
a time. They do not read source files, call an LLM, modify reviewer state, or
overwrite their input.

### 0.1 to 0.2 migration

The migration preserves all existing IDs and report behavior before the 0.2
writer becomes the default.

1. Copy nodes, edges, unknowns, metadata, and Evidence without loss.
2. Add empty `inferences`, `attribute_evidence`, and `identity_aliases` fields.
3. Copy element Evidence to first-class known attributes that the source syntax
   directly established. Do not assign it to arbitrary metadata.
4. When legacy metadata contains `type_inferred_from`, move that classification
   into an explicit Inference and set the fact type to `unknown`.
5. Preserve other legacy `component` types because 0.1 cannot reliably determine
   whether they were explicit or fallback. Record a migration warning as an
   Unknown instead of guessing.
6. Retain migration warnings until the original input is re-extracted by a 0.2
   adapter or a reviewer resolves them.

The migration golden set includes a minimal model, every node and edge type,
Mermaid inferred types, trust-boundary membership, LLM-merged metadata, and
models containing unknowns.

### Compatibility test matrix

Every schema change must pass:

* current JSON -> current model -> canonical JSON round trip;
* previous JSON -> migration -> current model;
* migrated current model -> all deterministic generators;
* current extractor output -> current golden artifacts;
* unsupported old and future version rejection; and
* migration idempotence at the target version.

## Stable Identity

### Model elements

IDs use a source-native stable key whenever one exists:

* Terraform resource address;
* OpenAPI operation ID, or normalized method and path when absent;
* Mermaid alias scoped by document and diagram; and
* an explicit document identifier for README facts.

Display names, descriptions, line numbers, confidence, and absolute paths are not
identity inputs. A rename changes identity only when the source-native key itself
changes.

Version 0.2 adds `identity_aliases` so a reviewer can explicitly connect an old
ID to a new ID. Diff matching follows this order:

1. exact ID;
2. explicit, unambiguous identity alias; and
3. no match.

Fuzzy name matching may be displayed as a review suggestion, but it never carries
facts or reviewer decisions automatically.

### Finding identity

Threat wording must not determine lifecycle identity. Each finding receives:

```text
finding_key = SHA-256(
  lens + rule_id + stable affected element IDs + stable catalog identifier
)
```

`catalog identifier` is the STRIDE category, ATT&CK technique ID, question rule,
or review-priority rule as appropriate.

A separate `context_fingerprint` hashes the canonical security-relevant subset of
the referenced facts and inferences. This lets wording improve without reopening
a decision while reopening it when supporting architecture changes.

Before lifecycle persistence is enabled, every lens output schema must expose a
stable `rule_id`. STRIDE and ATT&CK already do this; review-priority findings and
questions must add it without changing their existing display IDs. In the state
store, `subject_key` is the canonical JSON encoding of the sorted stable affected
element IDs, not a delimiter-concatenated display string.

Two hashes are computed for model snapshots:

* `semantic_fingerprint`: topology and security-relevant values, excluding
  Evidence ordering and operational metadata;
* `provenance_fingerprint`: canonical Evidence and inference lineage.

Model Diff reports semantic and provenance-only changes separately.

## Model Diff and Threat Delta

Inputs are an explicit reviewed baseline model and a current model. Neither is
loaded implicitly from the review-state database.

```text
system_model.base.json + system_model.current.json
    -> migrate both to current schema
    -> canonicalize
    -> element and attribute diff
    -> affected graph region
    -> rerun deterministic lenses
    -> finding-key and context comparison
    -> threat_delta.json / review.md
```

`model_diff.json` reports added, removed, changed, and provenance-only changes.
`threat_delta.json` reports new, changed, unchanged, and resolved finding
occurrences. `resolved` is an occurrence result, not a human lifecycle status.

The first implementation may rerun all deterministic rules and diff their
outputs. Affected-region execution is an optimization and must produce identical
results before it replaces the full run.

## Threat Review Lifecycle

Supported reviewer states are:

* `candidate`
* `reviewed`
* `accepted`
* `mitigated`
* `false_positive`
* `needs_context`

Finding occurrence (`active` or `resolved`) is separate from reviewer state.

Allowed transitions:

| From | To |
| --- | --- |
| candidate | reviewed, accepted, false_positive, needs_context |
| reviewed | accepted, mitigated, false_positive, needs_context |
| accepted | mitigated, false_positive, needs_context |
| mitigated | accepted, needs_context |
| false_positive | reviewed, needs_context |
| needs_context | reviewed, accepted, false_positive |

Every transition records the previous state, new state, reviewer, rationale, and
context fingerprint. Empty rationale is allowed for `reviewed`; decision states
such as `accepted`, `mitigated`, and `false_positive` require a rationale.

### Decision carry-forward

A decision carries forward only when both `finding_key` and
`context_fingerprint` match.

When the finding key matches but context changes:

* `accepted`, `mitigated`, and `false_positive` reopen as `candidate`;
* `reviewed` and `needs_context` reopen as `candidate`;
* the previous decision remains in history; and
* the delta explains which supporting facts or inferences changed.

No decision carries across a fuzzy identity match.

## SQLite Review State

SQLite is used only when lifecycle persistence is enabled. The default location
is explicitly supplied with `--state`; commands do not search a home directory or
silently create global state.

Minimum tables:

```sql
CREATE TABLE schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE baselines (
    name TEXT PRIMARY KEY,
    semantic_fingerprint TEXT NOT NULL,
    provenance_fingerprint TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE findings (
    finding_key TEXT PRIMARY KEY,
    lens TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    context_fingerprint TEXT NOT NULL,
    first_seen_model TEXT NOT NULL,
    last_seen_model TEXT NOT NULL,
    occurrence TEXT NOT NULL CHECK (occurrence IN ('active', 'resolved'))
);

CREATE TABLE review_decisions (
    finding_key TEXT PRIMARY KEY REFERENCES findings(finding_key),
    status TEXT NOT NULL,
    rationale TEXT NOT NULL,
    reviewer TEXT,
    context_fingerprint TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE decision_events (
    id INTEGER PRIMARY KEY,
    finding_key TEXT NOT NULL REFERENCES findings(finding_key),
    previous_status TEXT,
    new_status TEXT NOT NULL,
    rationale TEXT NOT NULL,
    reviewer TEXT,
    context_fingerprint TEXT NOT NULL,
    changed_at TEXT NOT NULL
);
```

Database migrations use `PRAGMA user_version`, run in one transaction, and are
tested against every supported prior state version. Foreign keys are enabled.
Local interactive use may enable WAL; CI may use the default journal mode to
avoid sidecar-file handling.

The database stores hashes, stable identifiers, decisions, and audit metadata.
It does not store raw input, Evidence excerpts, complete model JSON, LLM prompts,
or generated report bodies. Baseline model files remain explicit command inputs.

State files are created with owner-only permissions where the platform supports
it. SQLite does not provide encryption at rest, so the operator remains
responsible for protecting and retaining the file. Reviewer rationales are
length-limited, must not contain secrets or source excerpts, and are never printed
to logs. Reviewer identity is optional. An untrusted pull-request job may read an
approved baseline state artifact but cannot update review decisions.

## CLI Boundaries

Planned commands are explicit about read and write targets:

```bash
tm-ai model validate system_model.json
tm-ai model migrate system_model.json --to 0.2 --out system_model.v0.2.json

tm-ai diff system_model.base.json system_model.current.json \
  --out out/delta

tm-ai review apply out/threat_delta.json decisions.json \
  --state out/review-state.db

tm-ai check system_model.current.json \
  --baseline system_model.base.json \
  --state out/review-state.db \
  --fail-on-new-unreviewed high
```

`analyze`, `render`, and the existing `check --fail-on` behavior remain available
during migration. New delta-based gates stay opt-in and off by default.

## Delivery Sequence

### Stage 0: Observation contract — implemented

* Shared `CandidateObservation` and `ObservationBatch` schemas.
* Deterministic normalizer and provenance policy.
* README, Mermaid, OpenAPI, and Terraform adapter integration.
* Existing `extract_*` compatibility and golden-output preservation.

### Stage 1: Version-aware model I/O

* Add version detection, migration registry, `model validate`, and `model migrate`.
* Implement compatibility fixtures before changing the writer version.
* Continue writing 0.1 until all current generators pass against migrated 0.2
  models.

Rollback: disable the 0.2 writer; the 0.1 reader and artifacts remain unchanged.

### Stage 2: Evidence and explicit inference

* Add 0.2 schema types, `NodeType.UNKNOWN`, attribute Evidence, and Inference.
* Implement `ResolvedSystemModel` and conflict-to-Unknown behavior.
* Move Mermaid keyword classification and similar heuristics into inference rules.
* Update every deterministic lens to retain inference IDs in `derived_from`.

Rollback: continue reading 0.2 but render from the preserved 0.1-compatible fact
view while inference rules are corrected.

### Stage 3: Single-write 0.2

* Switch deterministic adapters and the writer to 0.2.
* Migrate LLM candidate review into the common Observation contract.
* Publish 0.2 JSON Schema and golden artifacts.

Rollback: use `model migrate` output only in a separate path; never overwrite the
last reviewed 0.1 model.

### Stage 4: Gold Standard evaluation

* Measure extraction accuracy separately from lens quality.
* Establish regression thresholds before implementing lifecycle gates.

### Stage 5: Model Diff and finding fingerprints

* Implement canonicalization, semantic/provenance fingerprints, stable matching,
  and full-rule Threat Delta.
* Keep affected-region execution disabled until equivalence tests pass.

### Stage 6: Review state and delta-based CI

* Add SQLite schema migrations and lifecycle transitions.
* Carry decisions only across identical context fingerprints.
* Add opt-in `new_high_unreviewed` gating after false-candidate behavior is
  measured.

## Definition of Done

The design is implemented only when:

* no generated observation can become a fact without human review;
* fact and inference provenance is visible and machine-validatable;
* 0.1 models migrate deterministically without changing stable IDs;
* unsupported schema versions fail clearly;
* all current Golden artifacts either remain unchanged or have an explicitly
  reviewed versioned replacement;
* Model Diff distinguishes semantic from provenance-only change;
* reviewer decisions survive wording changes but reopen on supporting-context
  changes;
* the default CLI still works without an LLM or persistent state; and
* no raw source content is stored in the review-state database or logs.

## Deferred Decisions

The following are intentionally outside this design:

* a GUI for reviewing observations or threats;
* multi-user synchronization of SQLite state;
* remote review-state services;
* fuzzy automatic identity matching;
* affected-region performance optimization;
* cloud, runtime, image, and office-document adapters; and
* risk aggregation across multiple independent systems.
