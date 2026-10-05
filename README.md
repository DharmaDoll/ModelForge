# ModelForge

Forge system understanding. Automate threat modeling.

ModelForge creates a first-draft threat model from repository artifacts. It reads
README, Markdown docs with Mermaid diagrams, OpenAPI, and Terraform files, builds a
structured `system_model.json`, then generates DFD, STRIDE, MITRE ATT&CK,
risk-priority, and clarification-question reports.

By default, ModelForge is deterministic and does not call external LLM APIs. No
API key is required unless an optional LLM mode is explicitly enabled.

## Quick Start

Requirements: Python 3.12+ and `uv`.

Turn the bundled payments-service example into a reviewable threat-model draft:

```bash
git clone https://github.com/DharmaDoll/ModelForge.git
cd ModelForge
uv run tm-ai analyze ./examples/sample-system --out ./out/sample-system
```

Open `out/sample-system/review.md` for the one-page summary, then
`out/sample-system/questions.md` for decisions to take back to the team. The
reports are generated locally without an API key or external LLM call. They
are review candidates, not confirmed vulnerabilities.

For a guided walkthrough, sample review scenarios, and a safe way to try your
own repository, see the [Japanese Quick Start](docs/quickstart.ja.md).

## Analyze Your Own Project

If your project uses common filenames, ModelForge can auto-discover inputs:

```bash
uv run tm-ai analyze /path/to/your/project --out ./out
```

Auto-discovery looks for:

* `README.md` or `readme.md` in the project root
* Markdown docs with Mermaid fenced blocks under the project tree
* `openapi.yaml`, `openapi.yml`, `openapi.json`, `swagger.yaml`, `swagger.yml`, or
  `swagger.json` in the project root
* `*.tf` Terraform files recursively, excluding `.terraform`

You can also pass files explicitly:

```bash
uv run tm-ai analyze /path/to/your/project \
  --readme /path/to/your/project/README.md \
  --doc /path/to/your/project/docs/architecture.md \
  --openapi /path/to/your/project/openapi.yaml \
  --terraform /path/to/your/project/main.tf \
  --out ./out
```

Use `--terraform` more than once when a project has multiple Terraform files.
Use `--doc` more than once when a project has multiple Markdown architecture docs.

## Render Existing Model

To regenerate reports from a reviewed or merged system model without re-reading
README, OpenAPI, or Terraform inputs:

```bash
uv run tm-ai render ./out/system_model.merged.json --out ./out/reviewed
```

The input file can be named `system_model.json`, `system_model.merged.json`, or
any other path that contains a valid ModelForge system model. The output directory
receives a normalized `system_model.json` plus `dfd.mmd`, `threats.md`,
`attack.md`, `risk.md`, `questions.md`, and `review.md`.

## Execution Flow

ModelForge first turns supported inputs into `system_model.json`. Every generated
artifact reads from that model instead of raw source files.

Deterministic input adapters first emit typed `CandidateObservation` records.
Each observation carries source evidence, an explicit provenance class, a
confidence value, and one proposed model change. The normalizer currently accepts
only fully confident deterministic observations by default; generated candidates
cannot be promoted directly, and human-reviewed candidates require an explicit
normalization policy. Existing `extract_*` Python APIs remain compatible and
return the normalized `SystemModel`.

The current adapters wrap extractor-produced model claims as deterministic
observations. That transport step does not independently verify every semantic
inference. In particular, Terraform resource references are modeled as
`references`, not runtime communication or storage flows. Public exposure is
recognized only from supported explicit resource attributes; unknown controls
remain questions and do not add review-priority points as if absent.

An experimental schema 0.2 defines explicit `Inference`, per-attribute evidence,
and reviewed identity aliases. Validate either version and make a separate,
deterministic 0.2 copy of an existing 0.1 model with:

```bash
uv run tm-ai model validate ./out/system_model.json
uv run tm-ai model migrate ./out/system_model.json \
  --to 0.2 --out ./out/system_model.v0.2.json
uv run tm-ai model validate ./out/system_model.v0.2.json
```

Migration never overwrites its input or an existing output. It moves legacy
Mermaid type guesses out of fact fields and records ambiguous legacy component
types as review unknowns. Keep the original source and reviewed 0.1 model for
comparison; migration does not verify old claims against source files.
`analyze`, `render`, `check`, and `candidates merge` still consume or emit 0.1;
do not pass a 0.2 model to those commands yet. No LLM is used by validation or
migration.

```mermaid
flowchart TD
  Inputs["README / Markdown + Mermaid / OpenAPI / Terraform"]
  Extract["Deterministic extractors"]
  Observations["CandidateObservation[]\nevidence + provenance + confidence"]
  Normalize["Policy validation + normalization"]
  Model["system_model.json\nsource of truth"]
  DFD["dfd.mmd"]
  STRIDE["threats.md"]
  ATTACK["attack.md"]
  Risk["risk.md"]
  Questions["questions.md"]
  Review["review.md\nCI / PR summary"]
  LLM["Optional LLM refinement\n--llm refine-questions"]
  Refined["questions_refined.md\nnot source of truth"]
  ExtractLLM["Optional LLM extraction\n--llm extract-readme"]
  Candidates["llm_candidates.json\nreview-only candidates"]
  Merge["Explicit merge\ntm-ai candidates merge"]
  Merged["system_model.merged.json\nreviewed model"]
  Render["Render from model\ntm-ai render"]

  Inputs --> Extract --> Observations --> Normalize --> Model
  Model --> DFD
  Model --> STRIDE
  Model --> ATTACK
  Model --> Risk
  Model --> Questions
  Model --> Review
  Questions -. opt-in only .-> LLM -.-> Refined
  Model -. minimal summary .-> LLM
  Inputs -. README text, opt-in only .-> ExtractLLM -.-> Candidates
  Model -. base model .-> Merge
  Candidates -. human review .-> Merge -.-> Merged -.-> Render
  Render -. regenerated .-> DFD
  Render -. regenerated .-> STRIDE
  Render -. regenerated .-> ATTACK
  Render -. regenerated .-> Risk
  Render -. regenerated .-> Questions
  Render -. regenerated .-> Review
```

Without `--llm`, the LLM branch is skipped and no external API is called.

## Design Documents

* [Canonical Model Evolution and Review State](docs/design/canonical-model-evolution.md)
  defines the planned 0.1-to-0.2 migration, Fact/Inference boundary, Evidence
  rules, stable diff identities, and SQLite-backed review lifecycle.

## Output Files

* `system_model.json`
* `dfd.mmd`
* `threats.md`
* `attack.md`
* `risk.md`
* `questions.md`
* `review.md`
* `questions_refined.md` when optional LLM question refinement is enabled
* `llm_candidates.json` when optional LLM README extraction is enabled

What they mean:

* `system_model.json` - the structured intermediate model and source of truth
* `dfd.mmd` - Mermaid data-flow diagram
* `threats.md` - deterministic STRIDE threat candidates
* `attack.md` - deterministic MITRE ATT&CK technique candidates
* `risk.md` - deterministic High / Medium / Low review priorities
* `questions.md` - missing information to ask reviewers or system owners
* `review.md` - compact deterministic summary for CI jobs and pull requests
* `questions_refined.md` - optional LLM-refined wording for `questions.md`; not
  the source of truth
* `llm_candidates.json` - optional LLM-extracted README candidates for review;
  not merged into `system_model.json`

Model facts in `system_model.json` include non-sensitive evidence pointers such as
source file, extractor, section/detail, and line when available. Generated reports
show `Derived from` model IDs and a short evidence summary for review traceability.

Mermaid node types are inferred only from explicit label or alias keywords. Ambiguous
or unsupported Mermaid nodes remain `component`.

Mermaid element IDs are scoped by the Markdown path relative to the analyzed
project, diagram number, and Mermaid alias. A type or display-name change does
not change a node ID. If an explicitly supplied document lies outside the
project directory, its ID uses a location-bound fallback and may change when
that file moves. Repeated aliases in distinct documents or diagrams remain
separate; conflicting labels for one alias inside a diagram fail validation.
Python callers using `extract_mermaid_markdown` directly should pass
`identity_root=project_root` to obtain the same IDs as `tm-ai analyze`.

For models generated before this identity change, preview possible old-to-new
Mermaid ID mappings with:

```bash
tm-ai model identity-preview old/system_model.json new/system_model.json \
  --out identity-preview.json
```

The preview never edits either model or carries reviewer decisions. It lists
multiple matches as ambiguous, requiring explicit review before any future
identity-alias migration.

Mermaid `subgraph` blocks and Terraform network resources are treated as explicit
trust boundaries when the input states them. Missing entry-point boundary
membership is reported in `questions.md`; ModelForge does not infer boundaries
from names alone.

When two inputs disagree on a security-relevant field, the field is left
unknown and a `model_conflict` question carries the competing evidence. The
Terraform parser is intentionally heuristic; it does not implement full HCL
evaluation, variable resolution, or deployment reachability analysis.

## Quality Evaluation

Run the deterministic, labeled-probe evaluation with:

```bash
tm-ai evaluate tests/fixtures/evaluation/manifest.json
```

The current six cases and 61 labels are seed regression examples, not an
expert-reviewed gold standard. The command reports TP/FP/TN/FN by lens and
marks expert-reviewed coverage explicitly. See [evaluation methodology](docs/evaluation.md)
for denominator definitions, scope, and limitations.

## Review Workflow

1. Run `tm-ai analyze`.
2. Review `out/system_model.json` first. It should not contain invented architecture.
3. Open `out/dfd.mmd` in a Mermaid viewer.
4. Review `out/risk.md`, then `out/threats.md`, `out/attack.md`, and `out/questions.md`.
5. Answer the questions or improve the input files, then run the command again.

Unknown information is expected. ModelForge records it as questions instead of
guessing.

## Optional LLM Refinement

LLM usage is opt-in. The default `tm-ai analyze` command never calls an external
LLM.

To refine deterministic clarification questions into a separate review artifact:

```bash
# Set OPENAI_API_KEY through your approved secret-management method first.
uv run tm-ai analyze ./examples/sample-system \
  --out ./out \
  --llm refine-questions
```

This writes `questions_refined.md` in addition to the deterministic artifacts.
It shows the original and proposed wording side by side for every question ID.
The source of truth remains `system_model.json` and `questions.md`. ModelForge
sends only question IDs, categories, and deterministic question text to the LLM;
it does not send the full model, evidence paths, or raw input files. The response
must match a JSON schema and preserve every question ID exactly; otherwise the
refinement fails without writing a new refined artifact. An existing artifact
from an earlier run may still be present, so check the command result before
using it. Set `MODELFORGE_LLM_MODEL` to override the default OpenAI model.

To ask an LLM to extract structured candidates from README free text:

```bash
# Set OPENAI_API_KEY through your approved secret-management method first.
uv run tm-ai analyze ./examples/sample-system \
  --out ./out \
  --llm extract-readme
```

This writes `llm_candidates.json`. These candidates are review-only and are not
merged into `system_model.json`. Unlike question refinement, this mode sends raw
README text to the LLM, so use it only for inputs that are approved for external
processing.

Recommended review flow:

```text
README
  ↓
--llm extract-readme
  ↓
llm_candidates.json
  ↓
human review
  ↓
explicit merge
  ↓
system_model.merged.json
  ↓
tm-ai render
  ↓
dfd.mmd / threats.md / attack.md / risk.md / questions.md
```

Do not treat `llm_candidates.json` as trusted input. After review, merge it
explicitly into a separate model file:

```bash
uv run tm-ai candidates merge ./out/system_model.json ./out/llm_candidates.json \
  --out ./out/system_model.merged.json
```

The merge command validates candidate schema, evidence, references, confidence,
and the final `SystemModel`. It does not overwrite deterministic model IDs.
Rejected or ambiguous candidates become review unknowns, which can then surface
as clarification questions after `tm-ai render`.

## GitHub Action

Use the repository's composite action to run deterministic threat modeling in a
consumer repository. The action auto-discovers supported inputs from `target` and
does not call an LLM or require an API key.

```yaml
name: Threat model

on:
  pull_request:

permissions:
  contents: read

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - id: model-forge
        uses: DharmaDoll/ModelForge@main
        with:
          target: .
          output-directory: model-forge-out
      - uses: actions/upload-artifact@v7
        with:
          name: threat-model
          path: ${{ steps.model-forge.outputs.artifact-path }}
          if-no-files-found: error
```

By default, `review.md` is also shown on the GitHub Actions job summary. The action
exposes `system-model-path` and `review-summary-path` for later validation or review
steps.

PR comments are opt-in because they require write permission. Add
`pull-requests: write` to the workflow permissions, then pass the token explicitly:

```yaml
permissions:
  contents: read
  pull-requests: write

# In the ModelForge action step:
with:
  target: .
  output-directory: model-forge-out
  pr-comment: "true"
  github-token: ${{ github.token }}
```

ModelForge creates or updates only the comment carrying its private marker. Fork
pull requests may receive a read-only token, so leave `pr-comment` disabled when
the workflow cannot grant comment permission. Pin `DharmaDoll/ModelForge` to a
release tag or commit SHA in production workflows.

The Action reports findings without failing by default. To make deterministic risk
candidates a CI gate, set `fail-on-risk` to `high`, `medium`, or `low`. The selected
rating and every higher rating will fail the Action:

```yaml
with:
  target: .
  output-directory: model-forge-out
  fail-on-risk: high
```

This gate evaluates the generated `system_model.json` with the deterministic risk
engine. It does not treat a candidate as a confirmed vulnerability; choose a
threshold only after calibrating the rules against the repository.

The same check is available locally or in custom CI workflows:

```bash
uv run tm-ai check ./model-forge-out/system_model.json --fail-on high
```

## Validation And Errors

ModelForge validates the generated graph before writing reports. Invalid references,
duplicate model IDs, blank required fields, missing inputs, and malformed OpenAPI or
Terraform files fail fast with `Error`, `Detail`, and `Hint` lines in the CLI.

## Development

```bash
uv run pytest
uv run ruff check .
uv run tm-ai analyze ./examples/sample-system --out ./out
```

The repository CI runs the same deterministic checks for pushes to `main` and pull
requests. It self-tests the composite action with the sample system, uses locked
dependencies, and uploads the result as the `sample-threat-model` workflow artifact.

Golden regression fixtures live in `tests/fixtures/golden/sample-system`. Update
them only when generated artifact changes are intentional.

## Supported Inputs

The MVP supports:

* README
* Markdown docs with Mermaid `flowchart` or `graph` fenced blocks
* OpenAPI / Swagger
* Terraform

Future versions may add Kubernetes, cloud inventory, CI/CD, source-code, SBOM, and
runtime telemetry ingestion.

## Package Layout

```text
threatmodel_ai/
  ingest/      input discovery for README, Markdown docs, OpenAPI, and Terraform
  extract/      README, Mermaid, OpenAPI, and Terraform extractors
  model/        Pydantic intermediate model, ids, merge, IO
  dfd/          Mermaid DFD renderer
  stride/       deterministic STRIDE rule engine
  attack/       deterministic MITRE ATT&CK technique mapping
  risk/         deterministic risk scoring
  questions/    clarification question generator
  llm/          optional LLM refinement interfaces
  report/       Markdown report renderers
  cli/          Typer CLI
```

## Design Philosophy

The LLM is not the source of truth. The source of truth is the intermediate model:

```text
Input Files
  ↓
Structured Extraction
  ↓
system_model.json
  ↓
DFD
  ↓
STRIDE Rules
  ↓
LLM Refinement
  ↓
Reports
```

LLM usage, when added, must be optional and limited to:

* extracting structure from unstructured text
* improving wording
* generating missing questions
* refining threat descriptions

## Security Note

This tool may process sensitive architecture and source-code information.

External LLM calls are disabled by default and require an explicit `--llm` mode.

## Threat Analysis

ModelForge currently generates deterministic threat-analysis views from the
same `system_model.json`:

* STRIDE candidates in `threats.md`
* MITRE ATT&CK Enterprise technique candidates in `attack.md`
* High / Medium / Low review priorities in `risk.md`
* A compact CI and pull-request summary in `review.md`

ATT&CK mappings are intentionally conservative. They describe plausible TTP
candidates implied by the modeled topology, not proof that an attack occurred.
