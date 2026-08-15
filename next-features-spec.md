# Backlog: ModelForge Core Enhancements & Features Spec

This document defines the actionable implementation tasks for ModelForge, focusing on enhancing threat detection accuracy, mitigating data privacy risks, and accelerating shift-left integration within the DevSecOps pipeline.

Task numbers are retained for continuity. Delivery priority follows dependencies:
Task 0, then Task 6, then Task 7, followed by the remaining tasks as their
foundations become available. Canonical model semantics and measurable regression
quality come before additional adapters or generative enrichment.

---

## Task 0: Canonical Model Semantics & Provenance (P0)
- **Objective**: Stabilize the meaning and trust model of `system_model.json` before expanding ingestion.
- **Design**: [Canonical Model Evolution and Review State](docs/design/canonical-model-evolution.md)
- **Requirements**:
  1. **Layer Separation**: Represent extractor output as candidate observations, normalize reviewed observations into facts, represent any inference explicitly with `based_on` and confidence, and keep security assessments in derived lens outputs.
  2. **Evidence Requirement**: Require provenance for accepted model elements and security-relevant attributes. Unsupported proposals remain candidates or unknowns.
  3. **Canonical Vocabulary**: Version the schema for nodes, edges, trust boundaries, actors, identities, interfaces, controls, assets, data stores, classifications, deployments, evidence, and unknowns.
  4. **Compatibility**: Add JSON Schema export, migration policy, round-trip tests, and versioned golden fixtures.

---

## Task 1: Hybrid Threat Analysis Engine (Static Rules + LLM)
- **Objective**: Establish a fail-safe analytical pipeline that suppresses LLM hallucinations while deterministically validating known STRIDE patterns.
- **Requirements**:
  1. **Frontend Processing**: Implement a deterministic `GraphAnalyzer` abstraction over the canonical system model. It must flag foundational STRIDE threats based on modeled element types and support reachability, entry-point, trust-boundary, and sensitive-data-path queries. NetworkX may be an internal implementation but is not a public requirement.
  2. **ATT&CK Mapping**: Generate MITRE ATT&CK Enterprise technique candidates from the same intermediate model without replacing STRIDE. ATT&CK findings must link back to model evidence and affected graph elements.
  3. **Context Enrichment**: Feed the output of the static rule engine as pre-established context into the LLM backend. The LLM may propose `ThreatCandidate` hypotheses and missing facts, but must not assert a threat or mutate accepted model facts.
  4. **Human-in-the-Loop (HITL)**: Define a structured JSON schema that supports `candidate`, `reviewed`, `accepted`, `mitigated`, `false_positive`, and `needs_context` lifecycle states. A GUI is not required for the MVP.

## Task 2: Data Privacy & Anonymization Guard
- **Objective**: Enforce an explicit external-transmission policy and use redaction as a defense-in-depth control, not as a guarantee that architecture data is safe to send.
- **Requirements**:
  1. **Pre-processing Pipeline**: Position this module as a mandatory gate before any data is dispatched to external LLM endpoints. Require explicit opt-in, a data-classification/policy decision, and minimum necessary context.
  2. **Dynamic Masking**: Intercept and mask proprietary variables, IP addresses, environment configurations, and cloud resource identifiers (e.g., AWS ARNs, DB endpoints) with abstract identifiers (e.g., `Service_A`, `DB_1`).
  3. **Reversible Mapping**: Where policy permits transmission, maintain a localized, secure in-memory or ephemeral mapping state to reversibly restore original resource names. Never persist mappings or include them in logs by default.
  4. **Structural Sensitivity**: Treat topology itself as potentially confidential even after identifiers are masked. A denied policy decision must prevent the call rather than fall back to redaction.

## Task 3: Local & On-Premises LLM Backend Support
- **Objective**: Provide a fully air-gapped, local inference option for enterprise environments restricted from leveraging external APIs.
- **Requirements**:
  1. **Abstraction Layer**: Decouple the inference client layer to introduce a flexible provider-switching architecture.
  2. **Connector Blocks**: Implement dedicated connector classes to interface with `Ollama` or `vLLM`, enabling seamless execution of open-source models (e.g., Llama-3, Mistral) within private VPCs or local developer workstations.

## Task 4: Architecture-as-Code (AaC) Ingestion Layer
- **Objective**: Automatically ingest threat modeling inputs directly from developers' daily engineering definitions.
- **Requirements**:
  1. **Common Adapter Contract**: Make each parser emit `CandidateObservation` records with source location, extractor identity, confidence/provenance class, and a proposed model change.
  2. **Mermaid Parser**: Extend the existing Mermaid parser to cover additional supported graph syntax without inferring ambiguous element types.
  3. **IaC Importer**: Extend the existing Terraform importer and add AWS SAM only after normalization, conflict, provenance, and unknown-handling tests exist for the common adapter contract.

## Task 5: Context-Aware Risk Scoring Engine
- **Objective**: Provide granular risk prioritization and sorting capabilities to prevent developer alert fatigue from automated outputs.
- **Requirements**:
  1. **Topology Valuation**: Rather than applying static threat catalog scores, implement a topology evaluator that assesses the specific architectural placement of an element (e.g., Public-facing DMZ vs. Isolated VPC subnet).
  2. **Review-Priority Matrix**: Calculate a deterministic review priority by combining exposure, asset criticality, trust crossing, control confidence, and attack feasibility. Do not label architecture candidates as CVSS scores or confirmed vulnerability severity.
  3. **Unknown Handling**: Missing classification or controls must be visible in the rationale and questions; unknown values must not be silently scored as known weaknesses.

## Task 6: Gold Standard Regression Testing Framework
- **Objective**: Programmatically detect detection degradation or regression caused by prompt tweaks or rule updates.
- **Requirements**:
  1. **Fixtures Setup**: Populate `tests/fixtures/` with baseline DFD pattern schemas representing known architectures (e.g., OWASP Juice Shop, standard microservices) paired with their expert-curated "Gold Standard" threat logs.
  2. **Validation Script**: Build an automated evaluation script that executes across these fixtures upon engine changes. Report model extraction precision/recall separately from threat recall, false-candidate rate, and question usefulness; include TPR, FPR, and FNR where fixture labels support them.
  3. **Mode Comparison**: Compare deterministic-only and deterministic-plus-LLM results while keeping the default unit-test suite independent of an LLM.

## Task 7: Model Diff, Threat Delta & Review Lifecycle (P1)
- **Objective**: Make architectural changes reviewable without forcing a full threat-model rereview on every run.
- **Requirements**:
  1. **Stable Diff**: Compare a reviewed baseline and current model using stable IDs, then report added, removed, and security-relevant changes to elements and attributes.
  2. **Affected Analysis**: Re-evaluate affected graph regions and emit new, changed, and resolved threat candidates.
  3. **Decision Carry-Forward**: Preserve explicit reviewer lifecycle decisions across runs when the supporting model facts are unchanged.
  4. **CI Policy**: Keep gates off by default and support conditions such as `new_high_unreviewed > 0`; candidate existence alone must not fail CI.

---

## Implementation Rules
- **Lean & AI-Native**: Keep code footprints minimal. For any persistent storage requirements, adhere strictly to a lightweight, `SQLite-first` engineering approach.
- **Shift-Left Priority**: To ensure security functions as a facilitator rather than a bottleneck, optimize all output interfaces to be modularly consumed by CI/CD workflows (e.g., GitHub Actions) or directly injected as Markdown comments into Pull Requests.
