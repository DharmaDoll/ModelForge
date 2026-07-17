# ModelForge

Forge system understanding. Automate threat modeling.

ModelForge creates a first-draft threat model from repository artifacts. It reads
README, OpenAPI, and Terraform files, builds a structured `system_model.json`, then
generates DFD, STRIDE, MITRE ATT&CK, and clarification-question reports.

The current MVP is deterministic and does not call external LLM APIs. No API key is
required.

## Quick Start

Requirements:

* Python 3.12+
* `uv`

Run the sample project:

```bash
git clone https://github.com/DharmaDoll/ModelForge.git
cd ModelForge
uv run tm-ai analyze ./examples/sample-system --out ./out
```

The generated files will be in `./out`.

## Analyze Your Own Project

If your project uses common filenames, ModelForge can auto-discover inputs:

```bash
uv run tm-ai analyze /path/to/your/project --out ./out
```

Auto-discovery looks for:

* `README.md` or `readme.md` in the project root
* `openapi.yaml`, `openapi.yml`, `openapi.json`, `swagger.yaml`, `swagger.yml`, or
  `swagger.json` in the project root
* `*.tf` Terraform files recursively, excluding `.terraform`

You can also pass files explicitly:

```bash
uv run tm-ai analyze /path/to/your/project \
  --readme /path/to/your/project/README.md \
  --openapi /path/to/your/project/openapi.yaml \
  --terraform /path/to/your/project/main.tf \
  --out ./out
```

Use `--terraform` more than once when a project has multiple Terraform files.

## Output Files

* `system_model.json`
* `dfd.mmd`
* `threats.md`
* `attack.md`
* `questions.md`

What they mean:

* `system_model.json` - the structured intermediate model and source of truth
* `dfd.mmd` - Mermaid data-flow diagram
* `threats.md` - deterministic STRIDE threat candidates
* `attack.md` - deterministic MITRE ATT&CK technique candidates
* `questions.md` - missing information to ask reviewers or system owners

## Review Workflow

1. Run `tm-ai analyze`.
2. Review `out/system_model.json` first. It should not contain invented architecture.
3. Open `out/dfd.mmd` in a Mermaid viewer.
4. Review `out/threats.md`, `out/attack.md`, and `out/questions.md`.
5. Answer the questions or improve the input files, then run the command again.

Unknown information is expected. ModelForge records it as questions instead of
guessing.

## Development

```bash
uv run pytest
uv run ruff check .
uv run tm-ai analyze ./examples/sample-system --out ./out
```

## Supported Inputs

The MVP supports:

* README
* OpenAPI / Swagger
* Terraform

Future versions may add Kubernetes, cloud inventory, CI/CD, source-code, SBOM, and
runtime telemetry ingestion.

## Package Layout

```text
threatmodel_ai/
  ingest/      input discovery for README, OpenAPI, and Terraform
  extract/      README, OpenAPI, and Terraform extractors
  model/        Pydantic intermediate model, ids, merge, IO
  dfd/          Mermaid DFD renderer
  stride/       deterministic STRIDE rule engine
  attack/       deterministic MITRE ATT&CK technique mapping
  questions/    clarification question generator
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

The current MVP does not call external LLM APIs.

## Threat Frameworks

ModelForge currently generates two deterministic threat-analysis views from the
same `system_model.json`:

* STRIDE candidates in `threats.md`
* MITRE ATT&CK Enterprise technique candidates in `attack.md`

ATT&CK mappings are intentionally conservative. They describe plausible TTP
candidates implied by the modeled topology, not proof that an attack occurred.
