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
* Permit an opt-in LLM challenger to propose grounded threat hypotheses in a
  separate review artifact. It cannot establish architecture facts, confirm
  vulnerabilities, alter deterministic findings, or drive CI gates by itself.
* Call risk output **review priority**, not vulnerability severity or CVSS.

## Progress Tracking

**ROADMAP.md is the strategy and dependency map.** It records why a capability
matters, its order, design constraints, release gates, and the technical boundary
observed in the working tree. Its "Current implementation" notes are snapshots,
not task checklists or claims that local work has shipped. Long-range input ideas
stay here without an Issue until they have a bounded delivery slice.

**GitHub Issues are the execution tracker.** Open an Issue when a current or
next-up slice has a concrete outcome, acceptance criteria, and test/documentation
work. Keep task checkboxes and blockers there, not in this roadmap. Link the
Issue to the relevant roadmap section and avoid duplicate Issues for the same
slice. Check off work only after code, tests, and documentation are verified and
committed; close the Issue with the completing commit or PR. Update this
roadmap's technical-boundary note when a milestone ships or its direction
changes. Local uncommitted work remains in progress.

| Roadmap delivery track | Execution tracker |
| --- | --- |
| P0 inference precision | [Issue #6 — evaluated baseline](https://github.com/DharmaDoll/ModelForge/issues/6) includes negative-case regression |
| P0 conflicts and identity | [Issue #4](https://github.com/DharmaDoll/ModelForge/issues/4) |
| P0 canonical 0.2 | [Issue #3](https://github.com/DharmaDoll/ModelForge/issues/3) |
| P1 first-run review usability | [Issue #5](https://github.com/DharmaDoll/ModelForge/issues/5) |
| P1 evaluated baseline | [Issue #6](https://github.com/DharmaDoll/ModelForge/issues/6) |
| P1 developer-answer review loop | [Issue #7](https://github.com/DharmaDoll/ModelForge/issues/7) |
| P1 business context and ingestion visibility | [Issue #2](https://github.com/DharmaDoll/ModelForge/issues/2) |
| P1 opt-in LLM threat challenger | [Issue #1](https://github.com/DharmaDoll/ModelForge/issues/1) |
| P1 Model Diff and threat delta | Roadmap only until stable identity and canonical 0.2 acceptance are ready |
| P1 reviewer lifecycle and CI | Roadmap only until Model Diff semantics are ready |
| P1 playbook-guided review questions | Roadmap only until the expert-reviewed baseline is ready |

Graph abstraction, additional adapters, and later phases remain roadmap-only
until a specific next delivery slice meets the Issue criteria above. An Issue
is not required for every paragraph or future input idea.

## Next Delivery Milestones

These milestones take priority over expanding the long-term input catalog.

### Delivery order and quality gates

The implementation is staged so that a larger schema or CI gate cannot amplify
unverified extraction claims:

1. **P0 — inference precision:** treat Terraform references as configuration
   relationships, not runtime flows; require explicit public exposure; do not
   score unknown controls as absent. Keep uncertainties in `questions.md`.
   This conservative baseline is implemented for the current rules. Expand it
   with labeled negative cases before adding more inference rules.
2. **P0 — conflicts and identity:** surface contradictory source claims as
   `model_conflict` unknowns with both evidence pointers. Never silently pick a
   security-relevant value. Scope Mermaid IDs by document and diagram, and
   preview legacy matches without transferring reviewer decisions. Define
   cross-source aliases and explicit migration fixtures before those decisions
   can be carried to a new identity.
   Document- and diagram-scoped Mermaid IDs plus a read-only legacy-ID preview
   are implemented. Cross-source identity aliases and acceptance/migration of
   reviewed identities remain pending; ambiguous legacy IDs are never mapped
   automatically. The Quick Start review also showed distinct nodes with the
   same display name; surface these as possible identity matches with their
   sources, without inventing an alias or a missing data flow.
   Terraform IDs and references are now scoped by source directory, retaining
   root-level IDs. This prevents separate local modules with the same resource
   names from merging. Same-directory duplicate declarations now produce a
   `model_conflict` Unknown with both source pointers; their nodes and
   dependent edges are not accepted. Do not automatically carry reviewer
   decisions from historical unscoped IDs to newly scoped IDs. Explicit
   Terraform module boundaries beyond source directories remain unmodeled.
3. **P0 — canonical 0.2:** separate observations, facts, inferences, and
   assessments in storage. Add attribute-level evidence and a version-aware
   reader/migrator before releasing 0.2. The version-aware inspection reader
   accepts explicit 0.1 and 0.2 artifacts; the existing observation wrapper is
   a transport contract, not yet
   proof that each proposed semantic claim is an accepted fact.
   A draft 0.2 schema, pure 0.1→0.2 migrator, non-serializing resolved view,
   and opt-in `model validate` / `model migrate` commands are implemented with
   unit and sample-system parity tests. `model validate --check-generators`
   exercises all deterministic lenses and report renderers in memory without
   publishing 0.2 artifacts. Versioned structural JSON Schema export is also
   available through `model schema`; semantic validation still requires
   `model validate`. An opt-in `model validate --require-attribute-evidence`
   audit now identifies missing element and security-attribute pointers in 0.2
   models; default validation remains compatible with legacy migrations until
   native fact acceptance can enforce the policy. Inference `based_on` now
   rejects unsupported paths and absent, unknown, or empty source claims. The
   opt-in audit also checks direct attribute Evidence on every cited inference
   basis, including names and Mermaid aliases.
   The internal 0.2 preview now cites applied
   inference IDs for candidates that change when those inferences are removed;
   this conservative lineage check is not yet a scalable, field-level trace.
   `analyze`, `render`, `check`, and
   candidate merge remain 0.1-only; 0.2 is not yet the default writer or part
   of the fact-acceptance policy.
4. **P1 — first-run review usability:** turn the sample's long question list
   into a navigable review queue without discarding Unknowns or Evidence. Make
   possible duplicate identities visible, distinguish assessment confidence
   from review priority, and verify the documented Quick Start in a clean
   environment. Detailed acceptance criteria follow below.
5. **P1 — evaluated baseline:** build expert-labeled positive and negative
   fixtures across extraction, STRIDE, ATT&CK, questions, and review priority.
   Measure false candidates and model precision before setting CI thresholds.
6. **P1 — developer-answer review loop:** capture answers to stable question
   IDs as sourced, reviewable observations. Preview conflicts and model changes
   before explicit acceptance; do not equate a developer's claim with verified
   implementation. Re-run deterministic analysis after accepted changes. The
   capture/preview workflow can precede Model Diff; carrying review decisions
   across runs depends on stable identity and diff semantics.
7. **P1 — business context and ingestion visibility:** capture business scope,
   assets, assumptions, and constraints as sourced, reviewable observations;
   report what each input adapter did and did not extract. Establish an honest
   baseline before adding diagram formats or LLM-generated context. The first
   `ingestion.json` slice reports selected-file and structured-proposal counts
   plus recognized/skipped Mermaid syntax and OpenAPI path/HTTP-operation
   declarations. Terraform now reports recognized resource blocks and ID
   collisions; unsupported HCL syntax and comparable coverage metrics remain
   pending. `architecture.md` and `spec.md` are already discovered as Markdown
   files, but only supported Mermaid flowcharts in them are modeled today;
   prose extraction and a typed business-context input remain pending.
8. **P1 — Model Diff:** stabilize semantic IDs and fingerprints, then compare a
   reviewed baseline with the current model. Initially produce a full,
   deterministic diff; optimize affected-graph re-analysis only after parity
   tests show it does not omit changed candidates.
9. **P1 — reviewer lifecycle and CI:** persist decisions separately from the
   architecture model. Add SQLite only once identity/diff semantics are stable.
   Keep CI gates opt-in, based on newly unreviewed candidates rather than the
   presence of any candidate.
10. **P1 — playbook-guided review questions:** pilot selected OWASP Secure Agent
   Playbook API and IaC checks as versioned question/verification guidance over
   supported model facts and unknowns. Evaluate usefulness and false prompts
   against expert-reviewed fixtures before expanding the catalog or adding an
   optional LLM discussion assistant.
11. **P1 — opt-in LLM threat challenger:** generate evidence-linked, conditional
    threat hypotheses in a separate review artifact, with explicit assumptions
    and verification steps. Evaluate against the deterministic baseline and
    require human disposition before any promotion to an accepted finding.
    Default reports and CI gates remain unchanged; see Phase 5 for delivery
    and evaluation criteria.

Each stage needs unit tests, reviewed regression fixtures, an unchanged default
no-LLM path, and documentation of known unknowns before moving to the next.

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
* The 0.1 schema is pinned and rejects unsupported future versions. This is a
  compatibility guard, not the planned 0.2 migration machinery.
* Conflicting node/edge security attributes become unknown plus an explicit
  review question; no later input may silently restore the disputed value.
* Mermaid aliases are scoped to a project-relative document and diagram;
  duplicate legacy IDs can be inspected with `tm-ai model identity-preview`.

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

### P1: First-Run Review Usability

The October 2026 Quick Start walkthrough completed successfully and produced
deterministic artifacts, but its sample output had 45 questions and several
visually repeated prompts. The DFD also showed separate same-name nodes from
different sources. These are presentation and identity-review problems, not
permission to merge evidence or suppress unknown facts.

Delivery order and acceptance criteria:

1. **Question triage (first):** group questions by reviewed subject and intent in
   the presentation layer, preserving every question ID, Unknown, and Evidence
   pointer in `system_model.json` and the detailed question artifact. Show a
   deterministic top 3–5 review queue in `review.md` with links or stable IDs
   leading to the full details. Keep the raw question count distinct from the
   number of grouped review tasks. Tests must cover multiple sources asking
   the same thing, similar wording about different elements, and stable output
   across reruns; grouping must never imply that an unanswered control exists.
   Implemented as presentation-only groups with a linked, deterministic
   five-task starting queue. The sample retains 45 underlying questions and
   displays 38 review tasks; source facts and question IDs remain unchanged.
2. **Unresolved identity visibility:** show exact-name cross-source duplicates
   and other evidence-backed possible matches in a separate review section,
   including source pointers and a reason for the suggestion. Keep all nodes
   and edges distinct in the canonical model and DFD until an explicit reviewed
   alias is accepted. Test both an unambiguous same-name suggestion and an
   ambiguous case where no alias can be accepted automatically.
   Implemented for normalized same-name nodes from distinct source files in
   `review.md`, including compact source hints, separate IDs, and ambiguous
   multi-node groups. Broader cross-source alias acceptance remains pending.
3. **Metric explanation:** add a short legend to `review.md` and the Quick Start
   separating STRIDE/ATT&CK candidate confidence from risk *review priority*.
   A high-confidence candidate may still have Low review priority; neither is
   vulnerability severity or proof of exploitability. Keep the scoring rules
   unchanged in this documentation/presentation step and add a regression
   assertion for the sample's mixed-scale output.
   Implemented as a short `review.md` legend and a Quick Start example showing
   high ATT&CK confidence alongside Low review priority for the same entry point.
4. **Cold-start verification:** run the documented clone and
   `uv run tm-ai analyze` commands from a clean checkout and Python 3.12+
   environment without preinstalled project dependencies or an LLM key. Verify
   the expected artifacts, `model validate`, deterministic rerun, and the documented
   high/low risk-check exit codes. Add an automated smoke test where practical
   and record any platform or network prerequisite that cannot be CI-tested.
   Verified in an isolated source copy without `.venv` or an LLM key using
   Python 3.13.5 and uv 0.11.21. All eight artifacts matched a rerun byte for
   byte; model validation and documented gate exit codes passed. Initial
   dependency download required network access. The Quick Start regression test
   now covers artifacts, validation, rerun equality, and exit codes; it does
   not emulate a fresh package download in CI.
5. **Evidence-path portability:** replace machine-specific absolute paths in
   generated Evidence for files inside the analyzed project with stable
   project-relative paths. Define how explicit inputs outside that root are
   represented before changing their output, and update golden fixtures and
   compatibility tests. Reports must not disclose the operator's home path
   merely because they are shared for review.
   Implemented for `analyze` output: in-project Evidence and known file-path
   metadata are project-relative. Explicit out-of-root inputs keep absolute
   pointers for traceability and require a sharing check; `render` preserves
   existing model paths.

Do not add an LLM dependency to any of these tasks. Re-run the Japanese Quick
Start as a reader after each presentation change; preserve the no-LLM path and
the existing model/DFD semantics.

### P1: Gold Standard Evaluation

Move reviewed measurement ahead of production use of LLM-generated threat
hypotheses or many new extractors. A shadow-mode prototype may help build the
evaluation set but must not change default reports or gates.

Current seed implementation: `tm-ai evaluate` runs six deterministic fixture
projects against 61 authored positive/negative probes. It reports confusion
matrices and defined-denominator ratios separately for model extraction,
STRIDE, ATT&CK, questions, and review priority. All labels are marked `seed`;
none have been independently expert-reviewed. See [evaluation methodology](docs/evaluation.md).

Deliverables:

* Add expert-reviewed fixture families for model extraction, STRIDE, ATT&CK,
  questions, and review priorities.
* Measure model extraction accuracy separately from threat-analysis quality.
* Report threat recall, false-candidate rate, question usefulness, and model
  extraction precision/recall. Where labels permit, also report TPR, FPR, and
  FNR.
* Compare deterministic-only, LLM-only experimental, and combined runs on the
  same inputs without requiring an LLM in the default unit-test suite. Record
  unsupported-claim rate, expert-reviewed usefulness, reviewer time, run-to-run
  variance, latency, and cost in addition to precision and recall.
* Make rule, schema, and prompt regressions visible in CI while keeping approval
  thresholds explicitly configured.

### P1: Developer-Answer Review Loop

Make developer conversations a traceable input to Continuous Threat Modeling,
not an unrecorded edit to a generated report.

Deliverables and acceptance criteria:

* Give each answer a stable question/subject reference, respondent, timestamp,
  scope/environment, original statement, and evidence pointer. Distinguish a
  developer assertion or intended design from independently verified behavior;
  neither confidence nor repetition is proof of implementation.
* Convert answers into typed `CandidateObservation` records. Provide a CLI
  import/preview/accept-or-reject workflow using the canonical acceptance policy;
  an answer must not silently overwrite a deterministic fact, resolve a conflict,
  or close an unknown. Preserve the original answer and reviewer decision in an
  auditable record separate from accepted model facts.
* On explicit acceptance, validate the updated model and regenerate DFD,
  questions, STRIDE, ATT&CK, and reports deterministically. Once Model Diff and
  reviewer lifecycle exist, show what changed and reopen decisions when their
  supporting context changes; never transfer decisions across ambiguous IDs.
* Test conflicting answers, unsupported claims, stale question IDs, changed
  environments, repeat imports, rejected answers, and deterministic reruns.
  Preserve a complete no-LLM workflow and avoid logging confidential answers.

### P1: Business Context and Ingestion Visibility

[Threat Thinker](https://github.com/melonattacker/threat-thinker) shows the
practical value of business context and diagram-import metrics. Adapt those
ideas to ModelForge's evidence-backed, no-LLM-default pipeline rather than
adopting LLM-completed architecture as fact or unreviewed threat generation.

Current boundary: auto-discovery already selects project-tree `*.md` files
(including `architecture.md` and `spec.md`) except the selected README and
ignored directories. The Markdown adapter currently models supported Mermaid
flowcharts, not surrounding prose. There is no dedicated business-context
input, CLI option, or typed canonical field. README title, summary, and named
lists are only limited architecture hints, not a substitute for business
context. Update the README's auto-discovery wording to distinguish file
selection from structured extraction.

Implementation order:

1. **Version the context contract.** Define a root auto-discovered
   `business_context.yaml` input, plus `--business-context` for an explicit
   YAML or JSON file. Include review scope/environment, business objectives,
   critical assets and classification, important workflows, availability
   needs, constraints, and assumptions.
   Give each claim a stable ID, source location, and status distinguishing a
   declared intention from independently verified behavior. Export a schema
   and add a read-only validation/preview command before any model mutation.
   Use a separate candidate artifact while the 0.2 writer and fact-acceptance
   policy are unfinished; do not hide typed context in arbitrary 0.1 metadata.
2. **Connect reviewed context to the canonical model.** Add typed 0.2 storage
   and an explicit accept/reject path by extending `CandidateObservation` with
   typed context claims and direct Evidence. Business priorities may guide
   questions and review ordering only after acceptance; a declared control or
   intended deployment must never override observed topology or count as an
   implemented safeguard. Conflicts become reviewable Unknowns/questions. Keep
   0.1 default outputs unchanged
   until 0.2 acceptance and migration are tested.
3. **Extract deliberately structured Markdown.** Keep recursive Markdown
   discovery, including `architecture.md` and `spec.md`, but initially parse
   only an explicit context block or narrowly specified headings/tables with
   line-level Evidence. Reuse the context contract and observation policy.
   Ordinary prose, examples, negations, future plans, and unsupported diagram
   syntax must not silently become architecture facts. Preserve explicit
   `--doc`, add exclude/auto-discovery controls, generated-output avoidance,
   and bounded file/size handling before enabling automatic prose extraction
   across the project tree.
4. **Make coverage and omissions visible.** Extend `ingestion.json` with counts
   of selected Markdown files, recognized structured sections, accepted or
   rejected proposals, and skipped/unsupported sections. Report parser
   coverage only where a defensible denominator exists; do not imply overall
   architecture completeness. Keep source text and machine-specific paths out
   of shared diagnostics.
5. **Evaluate before broadening free text.** Add authored positive/negative
   fixtures for `architecture.md`/`spec.md`, missing context, planned versus
   implemented controls, negation, conflicting sources, repeated runs, and
   adversarial text. Compare extraction precision, unsupported-fact rate,
   question usefulness, and reviewer effort against the current baseline.
   Only then consider an opt-in LLM prose extractor that emits separate,
   evidence-linked candidates under the External LLM Data Policy. It must not
   silently merge candidates or become a requirement for ordinary analysis.

Release gates: every stage has schema/CLI/golden tests, deterministic output,
portable Evidence, and Quick Start coverage. The first user-visible slice is
context validation and preview; report/risk/CI changes wait for reviewed 0.2
facts and measured benefit. A Markdown file with no recognized structure is
reported as unmodeled input, not treated as an error or invented topology.

Deliverables and acceptance criteria:

* Define a versioned, structured business-context input for review scope,
  critical assets, data sensitivity, workflows, availability needs, assumptions,
  and constraints. Map only supported claims into typed observations with source
  locations and verification status; retain unsupported narrative as context or
  questions. Reuse the developer-answer acceptance and conflict rules so a
  stated intention cannot silently override observed implementation.
* Emit deterministic per-input ingestion diagnostics: discovered inputs,
  recognized and parsed items, proposed and accepted observations, unresolved or
  conflicting claims, and unsupported or failed items. Define denominators and
  distinguish parser coverage from architectural completeness; never report a
  single misleading completeness percentage. Keep private source text and
  machine-specific paths out of shared summaries. Begin with per-adapter
  selected-file/batch/proposal counts and normalized-model counts, then add
  item-level diagnostics only when adapters can supply honest denominators.
  Mermaid now reports closed/unclosed fences, supported/unsupported diagram
  blocks, and parsed/skipped nonblank statements without changing extraction;
  OpenAPI reports declared paths and HTTP operations versus malformed entries
  skipped by its current parser. Terraform reports recognized resource blocks,
  files with none, and ID collisions, but cannot count all valid HCL resources
  with its current heuristic. These are not architectural-completeness metrics.
* Add positive and negative fixtures for absent context, conflicting scope,
  unverified controls, partially parsed diagrams, and reruns. Evaluate whether
  context improves question usefulness and threat relevance without increasing
  unsupported model facts or silently suppressing unknowns.
* If optional retrieval or LLM discussion is added later, select minimum
  necessary, approved context under the External LLM Data Policy. A local
  knowledge-base lookup does not itself authorize transmitting retrieved text
  to an external provider.

### P1: Playbook-Guided Review Questions

Use the [OWASP Secure Agent Playbook](https://github.com/OWASP/secure-agent-playbook)
as a source of review *methodology*, not as an executable dependency or an
authority for architecture facts. Pilot its
[API Security Review](https://github.com/OWASP/secure-agent-playbook/blob/main/plugins/code-security-skills/plays/api-security-review.md)
and [IaC Security Review](https://github.com/OWASP/secure-agent-playbook/blob/main/plugins/code-security-skills/plays/iac-security-review.md)
procedures because OpenAPI and Terraform are current input types.

Deliverables and acceptance criteria:

* Curate a small, versioned mapping from supported model facts/unknowns to
  specific review questions, verification steps, and source references. A
  missing declaration can produce a question, but must not be treated as a
  missing control or a confirmed vulnerability. Keep question IDs and evidence
  links stable and deduplicate at the review-presentation layer only.
* Compare question usefulness, unsupported-question rate, and duplicates with
  the deterministic baseline on expert-reviewed positive and negative fixtures.
  Do not increase default question volume merely to cover a checklist.
* Keep active API testing, source-code vulnerability scanning, and autonomous
  security agents outside this milestone. Consider the playbook's
  [multi-agent threat-model procedure](https://github.com/OWASP/secure-agent-playbook/blob/main/plugins/ai-security-skills/plays/multi-agentic-threat-model.md)
  only when agent-system modeling becomes an explicit supported domain.
* Record upstream version and attribution for any adapted material. The
  playbook is [CC BY 4.0](https://github.com/OWASP/secure-agent-playbook/blob/main/LICENSE.md);
  do not copy its templates or text without the required attribution.

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
* Optionally discuss approved model context and developer answers to propose
  follow-up questions, attack paths, and verification steps; retain every
  suggestion as a review candidate, never an accepted fact or closed finding
* Run an opt-in, read-only threat-hypothesis challenger over the canonical model
  to find plausible scenarios missed by deterministic rules

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
* Hypotheses must cite model element IDs and Evidence, distinguish established
  prerequisites from assumptions, and remain separate from `threats.md`,
  `system_model.json`, review-priority scores, and CI gates until reviewed
* Every external transmission must follow the External LLM Data Policy above

Challenger delivery sequence:

1. Define a versioned `threat_hypotheses.json` candidate schema with cited model
   IDs, Evidence pointers, assumptions, missing prerequisites, and proposed
   verification steps. Reject nonexistent references and unsupported certainty.
2. Add an opt-in shadow mode that uses only approved, minimum-necessary context;
   keep deterministic output and no-LLM operation unchanged.
3. Evaluate rules-only, LLM-only experimental, and combined outputs against
   independently reviewed positive and negative cases, including repeated runs
   and adversarial source text. Publish quality, reviewer-effort, latency, and
   cost tradeoffs before considering any default workflow change.
4. Require explicit human disposition before a hypothesis can become an
   accepted finding. Never promote its architectural assumptions to facts by
   confidence alone.

Current implementation:

* `questions_refined.md` is an optional wording artifact for reviewer convenience
* `llm_candidates.json` is an optional README extraction artifact for human review
* `tm-ai candidates merge` explicitly merges reviewed candidates into a separate model
* LLM candidates are not automatically merged into `system_model.json`
* The versioned `threat_hypotheses.json` contract has structural schema export,
  read-only exact-model Evidence validation, and an opt-in shadow generator for
  selected one-hop model slices. It requires operator-attested classification
  and explicit external-LLM approval. A separate local review-state JSON now
  records `investigate`, `needs_context`, or `rejected` events with a reviewer,
  rationale, timestamp, and exact model/batch binding. This is triage, not
  accepted-finding promotion. Comparative evaluation and promotion remain
  pending; hypothesis IDs are stable for identical normalized proposal text,
  not semantic paraphrases.

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
* Threat Dragon import/export round-trip after stable model IDs and review-state
  semantics: preserve source layout and cell identity where possible, attach
  evidence-linked threat candidates, and test no-op round trips and ambiguous
  mappings. Keep the canonical model authoritative rather than treating an
  exported diagram as a second source of truth.
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
