# Backlog: ModelForge Core Enhancements & Features Spec

This document defines the actionable implementation tasks for ModelForge, focusing on enhancing threat detection accuracy, mitigating data privacy risks, and accelerating shift-left integration within the DevSecOps pipeline.

---

## Task 1: Hybrid Threat Analysis Engine (Static Rules + LLM)
- **Objective**: Establish a fail-safe analytical pipeline that suppresses LLM hallucinations while deterministically validating known STRIDE patterns.
- **Requirements**:
  1. **Frontend Processing**: Implement a deterministic topology analysis layer utilizing `NetworkX` or similar libraries to parse Data Flow Diagrams (DFDs). It must automatically flag foundational STRIDE threats based on element types (Processes, Data Stores, Trust Boundaries, External Entities).
  2. **Context Enrichment**: Feed the output of the static rule engine as pre-established context into the LLM backend. The LLM should strictly focus on refining and contextualizing advanced threat scenarios based on attributes like Internet exposure or data classification.
  3. **Human-in-the-Loop (HITL)**: Define a structured JSON schema output that seamlessly enables a security engineer UI to "Approve," "Reject," or "Modify" generated threats.

## Task 2: Data Privacy & Anonymization Guard
- **Objective**: Anonymize sensitive assets in source code or Infrastructure-as-Code (IaC) configuration files prior to external LLM API transit to prevent data leakage.
- **Requirements**:
  1. **Pre-processing Pipeline**: Position this module as a mandatory gate before any data is dispatched to external LLM endpoints.
  2. **Dynamic Masking**: Intercept and mask proprietary variables, IP addresses, environment configurations, and cloud resource identifiers (e.g., AWS ARNs, DB endpoints) with abstract identifiers (e.g., `Service_A`, `DB_1`).
  3. **Reversible Mapping**: Maintain a localized, secure in-memory or ephemeral mapping state to reversibly restore the original resource names upon receiving the analysis, ensuring a white-box report output for local developers.

## Task 3: Local & On-Premises LLM Backend Support
- **Objective**: Provide a fully air-gapped, local inference option for enterprise environments restricted from leveraging external APIs.
- **Requirements**:
  1. **Abstraction Layer**: Decouple the inference client layer to introduce a flexible provider-switching architecture.
  2. **Connector Blocks**: Implement dedicated connector classes to interface with `Ollama` or `vLLM`, enabling seamless execution of open-source models (e.g., Llama-3, Mistral) within private VPCs or local developer workstations.

## Task 4: Architecture-as-Code (AaC) Ingestion Layer
- **Objective**: Automatically ingest threat modeling inputs directly from developers' daily engineering definitions.
- **Requirements**:
  1. **Mermaid Parser**: Build a parser capable of evaluating `Mermaid.js` graph syntaxes to extract nodes (assets) and edges (data flows) automatically.
  2. **IaC Importer**: Develop modular ingestion parsers for `Terraform` or `AWS SAM` configurations, tracing resource dependencies and mapping them cleanly into ModelForge's internal unified JSON schema.

## Task 5: Context-Aware Risk Scoring Engine
- **Objective**: Provide granular risk prioritization and sorting capabilities to prevent developer alert fatigue from automated outputs.
- **Requirements**:
  1. **Topology Valuation**: Rather than applying static threat catalog scores, implement a topology evaluator that assesses the specific architectural placement of an element (e.g., Public-facing DMZ vs. Isolated VPC subnet).
  2. **Dynamic Matrix**: Calculate a CVSS-aligned dynamic risk rating (High, Medium, Low) by compounding the attack surface exposure with asset criticality (data classification tier), sorting the backlog by real business impact (BI).

## Task 6: Gold Standard Regression Testing Framework
- **Objective**: Programmatically detect detection degradation or regression caused by prompt tweaks or rule updates.
- **Requirements**:
  1. **Fixtures Setup**: Populate `tests/fixtures/` with baseline DFD pattern schemas representing known architectures (e.g., OWASP Juice Shop, standard microservices) paired with their expert-curated "Gold Standard" threat logs.
  2. **Validation Script**: Build an automated evaluation script that executes across these fixtures upon engine changes to output quantitative metrics: True Positive Rate (TPR), False Positive Rate (FPR), and False Negative Rate (FNR).

---

## Implementation Rules
- **Lean & AI-Native**: Keep code footprints minimal. For any persistent storage requirements, adhere strictly to a lightweight, `SQLite-first` engineering approach.
- **Shift-Left Priority**: To ensure security functions as a facilitator rather than a bottleneck, optimize all output interfaces to be modularly consumed by CI/CD workflows (e.g., GitHub Actions) or directly injected as Markdown comments into Pull Requests.
