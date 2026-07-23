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
* LLM output must be validated before it can update `system_model.json`
* LLM extraction must produce structured candidates, not free-form reports
* Unsupported or ambiguous facts must remain `unknown` or become clarification questions
* External LLM calls must be opt-in
* Unit tests must mock LLM interactions

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

Future work:

* GitHub Actions
* PR comments
* Jira tickets
* Threat Dragon export
* AWS Config ingestion
* Kubernetes ingestion
* SBOM integration


# Phase X: Input Intelligence (Multimodal Ingestion)

The long-term goal of this project is to support threat modeling from **any artifact that describes a system**, not just structured files.

The ingestion pipeline should become increasingly multimodal, allowing security engineers and developers to provide whatever documentation is already available.

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
