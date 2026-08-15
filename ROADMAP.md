# ModelForge Roadmap

This roadmap treats ModelForge as an evidence-backed system modeling and threat
analysis engine. Threat modeling is one deterministic lens over the canonical
system model; the model and its provenance remain the product foundation.

## Planning Principles

The following rules apply to every phase:

* Evolve the canonical model before adding more input adapters.
* Keep observations, accepted facts, explicit inferences, and security
  assessments distinguishable.
* Require provenance for accepted facts and references from derived outputs back
  to the facts or inferences that support them.
* Treat STRIDE and MITRE ATT&CK as independent lenses over the same model. Do not
  derive one by mechanically translating the other.
* Preserve unknowns instead of filling gaps with assumptions.
* Treat all LLM output as a candidate until it passes validation and explicit
  human review.
* Call risk output **review priority**, not vulnerability severity or CVSS.

## Next Delivery Milestones

These milestones take priority over expanding the long-term input catalog.

### P0: Canonical Model Semantics

Define and version the meaning of `system_model.json` before broadening its
sources.

Detailed design: [Canonical Model Evolution and Review State](docs/design/canonical-model-evolution.md)

Current implementation:

* README, Mermaid, OpenAPI, and Terraform adapters emit a shared, versioned
  `ObservationBatch` containing typed `CandidateObservation` records.
* Observations carry evidence, provenance class, confidence, and exactly one
  proposed system, node, edge, or unknown change.
* The deterministic pipeline normalizes batches before merging the canonical
  model. Generated observations cannot be normalized directly, and reviewed
  observations require an explicit acceptance policy.
* Existing `extract_*` APIs still return `SystemModel` for compatibility and now
  use the same observation normalizer internally.

Deliverables:

* Publish a versioned canonical vocabulary covering nodes, edges, trust
  boundaries, actors, identities, interfaces, controls, assets, data stores,
  data classification, deployments, evidence, and unknowns.
* Introduce a common `CandidateObservation` contract for extractor output. An
  observation records the source, extractor, location, confidence/provenance
  class, and proposed model change without becoming a fact automatically.
* Normalize reviewed observations into accepted model facts. Keep explicit
  inferences separate and require `based_on` references plus confidence.
* Keep security assessments in lens-specific outputs and require `derived_from`
  references to model facts or explicit inferences.
* Require evidence on every accepted node, edge, boundary membership, and
  security-relevant attribute. Missing evidence must fail validation or remain an
  unknown; it must not silently become a fact.
* Add schema-version compatibility tests, migration policy, JSON Schema export,
  and round-trip validation fixtures before the next schema version is released.

Goal:

```text
Raw artifact
  -> CandidateObservation[]
  -> evidence and policy validation
  -> accepted facts + explicit inferences + unknowns
  -> system_model.json
```

### P1: Gold Standard Evaluation

Move regression measurement ahead of adding LLM-generated threat context or many
new extractors.

Deliverables:

* Add expert-reviewed fixture families for model extraction, STRIDE, ATT&CK,
  questions, and review priorities.
* Measure model extraction accuracy separately from threat-analysis quality.
* Report threat recall, false-candidate rate, question usefulness, and model
  extraction precision/recall. Where labels permit, also report TPR, FPR, and
  FNR.
* Compare deterministic-only and deterministic-plus-LLM runs without requiring
  an LLM in the default unit-test suite.
* Make rule, schema, and prompt regressions visible in CI while keeping approval
  thresholds explicitly configured.

### P1: Model Diff and Threat Delta

Make architectural change, rather than full report regeneration, the center of
Continuous Threat Modeling.

Deliverables:

* Compare a reviewed baseline model with a current model using stable element
  identities.
* Emit deterministic additions, removals, and security-relevant attribute
  changes for nodes, edges, assets, controls, and trust-boundary crossings.
* Re-run analysis for affected graph regions and emit only new, changed, and
  resolved threat candidates as a `ThreatDelta`.
* Add a threat-review lifecycle with at least `candidate`, `reviewed`,
  `accepted`, `mitigated`, `false_positive`, and `needs_context` states.
* Preserve reviewer decisions across runs through stable IDs and explicit
  baseline state.
* Gate CI on explicitly configured conditions such as new, unreviewed High
  candidates; do not fail merely because any candidate exists. Keep all gates
  off by default.

Goal:

```text
reviewed baseline + current model
  -> ModelDiff
  -> affected graph analysis
  -> ThreatDelta
  -> human review / optional CI gate
```

### P1: Unified Input Pipeline

Migrate existing extractors to one trust model before adding multimodal inputs.

Deliverables:

* Use the same Candidate Observation -> Normalization -> Evidence Validation
  pipeline for deterministic parsers, LLMs, vision systems, source analysis, and
  runtime observations.
* Define deterministic conflict, deduplication, precedence, and identity rules.
* Keep source-specific parsing outside the canonical model package.
* Add new adapters only with extraction fixtures, provenance tests, conflict
  tests, and unknown-handling tests.

### P1: Graph Analysis Abstraction

Add a small graph-analysis interface for reachability, trust-boundary crossings,
entry-point paths, and sensitive-data paths. NetworkX may implement this
interface, but it is not part of the public model or extractor contract.

### P1: External LLM Data Policy

External transmission remains opt-in. Before any external LLM call, enforce:

* an explicit user choice;
* a data-classification/policy decision;
* minimum necessary context; and
* optional reversible redaction where policy permits transmission.

Redaction is a defense-in-depth control, not proof that architectural data is
safe to transmit. Local and on-premises providers may be added behind the same
provider interface, but cannot bypass candidate validation.

## Phase 1: Core Model

* Define Pydantic schemas
* Implement `system_model.json`
* Add validation
* Add merge logic

Goal:

```text
README / OpenAPI / Terraform
  ↓
system_model.json
```

## Phase 2: DFD Generation

* Generate Mermaid DFD
* Show actors, components, data flows
* Show trust boundaries where possible

Goal:

```text
system_model.json
  ↓
dfd.mmd
```

## Phase 3: STRIDE Rule Engine

* Implement deterministic rules
* Generate threats without LLM
* Map threats to data flows and components

Goal:

```text
system_model.json
  ↓
threats.md
```

## Phase 3.5: MITRE ATT&CK Mapping

* Generate deterministic MITRE ATT&CK Enterprise technique candidates
* Keep ATT&CK mappings separate from STRIDE categories
* Map candidates to model evidence, affected nodes, and affected edges
* Start with public entrypoints, authenticated surfaces, insecure transport,
  storage mutation paths, and modeled secrets
* Keep technique catalog data curated and version-reviewable

Goal:

```text
system_model.json
  ↓
attack.md
```

STRIDE and ATT&CK remain separate outputs produced from the same canonical model.
ATT&CK candidates must not be generated by translating STRIDE categories.

## Phase 4: Missing Questions

* Detect missing authentication info
* Detect missing authorization info
* Detect missing data classification
* Detect missing logging and monitoring info
* Detect missing rate limit info

Goal:

```text
system_model.json
  ↓
questions.md
```

## Phase 5: Optional LLM

LLM support should enhance deterministic outputs, not replace them.

Recommended initial uses:

* Extract structured system model candidates from README and architecture docs
* Convert natural-language design notes into proposed nodes, edges, unknowns, and evidence
* Refine wording for deterministic STRIDE, ATT&CK, risk, and mitigation descriptions
* Improve clarification question wording
* Assist with non-structured document ingestion such as ADRs, design notes, and wiki exports

Constraints:

* LLM output must never be the source of truth
* LLM-generated architecture or threat context must remain a candidate until
  validated and explicitly reviewed
* LLM output must be validated before it can update `system_model.json`
* LLM extraction must produce structured candidates, not free-form reports
* Unsupported or ambiguous facts must remain `unknown` or become clarification questions
* External LLM calls must be opt-in
* Unit tests must mock LLM interactions
* Threat-context candidates must state supporting facts, missing facts, and
  confidence; unsupported hypotheses should become clarification questions
* Every external transmission must follow the External LLM Data Policy above

Current implementation:

* `questions_refined.md` is an optional wording artifact for reviewer convenience
* `llm_candidates.json` is an optional README extraction artifact for human review
* `tm-ai candidates merge` explicitly merges reviewed candidates into a separate model
* LLM candidates are not automatically merged into `system_model.json`

Candidate merge policy:

Merge support is explicit:

```bash
tm-ai candidates merge out/system_model.json out/llm_candidates.json \
  --out out/system_model.merged.json
```

The merge step must validate candidate schema, evidence, references, confidence,
and the final model. It must not overwrite deterministic facts without explicit
review. Unsupported or ambiguous candidates should remain as unknowns or
clarification questions.

Goal:

```text
Unstructured Docs
  ↓
LLM structured candidates
  ↓
llm_candidates.json
  ↓
Human review
  ↓
Explicit merge
  ↓
Validation
  ↓
system_model.json or system_model.merged.json
```

## Phase 6: DevSecOps Integration

Current implementation:

* GitHub Actions runs Ruff, Pytest, and the deterministic sample analysis
* A reusable composite action analyzes supported inputs in consumer repositories
* Sample threat-model outputs are retained as a workflow artifact for review
* CI uses locked dependencies and does not require an LLM or API key
* `review.md` provides a compact job summary and optional marker-scoped PR comment
* An opt-in `tm-ai check` risk threshold can fail CI on selected candidate ratings

The current threshold gate remains off by default. Its next evolution should use
the reviewed baseline and fail only on configured threat-delta conditions, such
as newly introduced, unreviewed High candidates.

Future work:

* Model Diff and Threat Delta in pull requests
* Threat-review lifecycle and persistence of reviewer decisions
* Jira tickets
* Threat Dragon export
* AWS Config ingestion
* Kubernetes ingestion
* SBOM integration


# Phase X: Input Intelligence (Multimodal Ingestion)

The long-term goal of this project is to support threat modeling from **any artifact that describes a system**, not just structured files.

The ingestion pipeline should become increasingly multimodal, allowing security engineers and developers to provide whatever documentation is already available.

This phase starts only after the canonical semantics and unified input pipeline
milestones above. Every adapter emits `CandidateObservation` records; no adapter,
LLM, or vision component writes accepted model facts directly.

## Structured Inputs

Examples:

* OpenAPI / Swagger
* AsyncAPI
* GraphQL Schema
* Terraform
* CloudFormation
* AWS CDK
* Pulumi
* Kubernetes Manifests
* Helm Charts
* Docker Compose
* Dockerfiles
* GitHub Actions
* GitLab CI
* Jenkins Pipeline
* Azure DevOps Pipelines
* Buildkite Pipelines
* Bazel Configuration
* Package manifests (package.json, pom.xml, go.mod, Cargo.toml)
* SBOM (CycloneDX, SPDX)
* VEX documents
* IAM Policies
* OPA / Rego Policies

---

## Cloud Infrastructure

Support direct ingestion from cloud providers.

Examples:

* AWS Config
* AWS Organizations
* AWS Resource Explorer
* AWS IAM
* AWS Security Hub
* AWS Inspector
* Azure Resource Graph
* Azure Defender
* GCP Asset Inventory
* GCP Security Command Center

---

## Source Code

Extract architecture directly from source code.

Examples:

* REST Controllers
* GraphQL Resolvers
* gRPC Services
* Message Queue Producers
* Consumers
* ORM Models
* Authentication Middleware
* Authorization Middleware
* Routing Definitions

Future capabilities:

* Call Graph Extraction
* Dependency Graph
* Data Flow Analysis
* Secret Detection
* Trust Boundary Detection

---

## Runtime Telemetry

Support runtime-generated system models.

Examples:

* OpenTelemetry
* eBPF
* Service Mesh
* Envoy
* Istio
* VPC Flow Logs
* CloudTrail
* Kubernetes Audit Logs
* Application Logs

This enables Continuous Threat Modeling.

---

## Documents

Support architecture extraction from office documents.

Examples:

* PDF
* Microsoft Word (.docx)
* PowerPoint (.pptx)
* Excel (.xlsx)
* Markdown
* HTML
* Confluence Export
* Notion Export
* Wiki Pages
* ADR Documents
* Design Documents
* Security Review Documents
* RFCs
* Meeting Minutes

---

## Images

Support image understanding.

Examples:

* Architecture Diagrams
* Network Diagrams
* DFD
* UML
* Sequence Diagrams
* ER Diagrams
* Whiteboard Photos
* Screenshots
* Handwritten Drawings

Future capabilities:

* OCR
* Diagram Understanding
* Automatic Component Detection
* Trust Boundary Recognition
* Data Flow Recognition

---

## Natural Language

Support free-form descriptions.

Examples:

* Product Requirement Documents
* Slack Discussions
* Teams Chats
* Email Threads
* Design Discussions
* User Stories
* Threat Modeling Workshop Notes
* Security Questionnaires

LLMs should transform unstructured text into structured system models.

---

## Existing Security Tools

Leverage outputs from existing security products.

Examples:

* OWASP Threat Dragon
* Microsoft Threat Modeling Tool
* PyTM
* DefectDojo
* Dependency-Track
* Trivy
* Semgrep
* CodeQL
* SonarQube
* Wiz
* Prisma Cloud
* Lacework
* Orca Security

---

## Future Input Sources

Potential future integrations include:

* GitHub Repository Graph
* GitHub Dependency Graph
* GitHub Code Search
* GitHub Copilot Workspace
* IDE Plugins
* MCP Servers
* AI Agent Memory
* Enterprise CMDB
* ServiceNow CMDB
* Backstage Catalog
* Internal Knowledge Graphs
* Enterprise RAG Systems

---

## Vision

Ultimately, every artifact that contains architectural knowledge should become a valid input.

Regardless of whether the information originates from source code, cloud infrastructure, documentation, diagrams, or human conversation, the system should normalize all inputs into the same intermediate representation (`system_model.json`).

This unified representation enables deterministic DFD generation, STRIDE analysis, continuous threat modeling, and future AI-assisted security workflows.
