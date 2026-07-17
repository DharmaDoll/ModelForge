# ModelForge
`Forge system understanding. Automate threat modeling.`  

ModelForge is an AI-native platform that transforms code, cloud infrastructure,
architecture diagrams, documents, and natural language into a unified system model.

From this model, it automatically generates DFDs, applies STRIDE-based threat analysis,
identifies missing information, and produces review-ready threat modeling artifacts.

## threatmodel-ai

AI-assisted threat modeling tool.

This tool generates a reviewable threat modeling draft from repository inputs.

## MVP Inputs

* README
* OpenAPI
* Terraform

## MVP Outputs

* `system_model.json`
* `dfd.mmd`
* `threats.md`
* `attack.md`
* `questions.md`

## Usage

```bash
tm-ai analyze ./examples/sample-system \
  --readme ./examples/sample-system/README.md \
  --openapi ./examples/sample-system/openapi.yaml \
  --terraform ./examples/sample-system/main.tf \
  --out ./out
```

The command writes:

* `out/system_model.json`
* `out/dfd.mmd`
* `out/threats.md` - STRIDE threat candidates
* `out/attack.md` - MITRE ATT&CK technique candidates
* `out/questions.md`

Input paths are optional when files use the default names under the target directory:

```bash
tm-ai analyze ./examples/sample-system --out ./out
```

## Development

```bash
uv run pytest
uv run ruff check .
uv run tm-ai analyze ./examples/sample-system --out ./out
```

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

The LLM is not the source of truth.

The source of truth is the intermediate model:

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

## MVP Scope

The MVP should work without an LLM.

LLM usage is optional and should only be used for:

* extracting structure from unstructured text
* improving wording
* generating missing questions
* refining threat descriptions

## Security Note

This tool may process sensitive architecture and source-code information.

External LLM calls must be disabled by default.

The current MVP does not call external LLM APIs.

## Threat Frameworks

ModelForge currently generates two deterministic threat-analysis views from the
same `system_model.json`:

* STRIDE candidates in `threats.md`
* MITRE ATT&CK Enterprise technique candidates in `attack.md`

ATT&CK mappings are intentionally conservative. They describe plausible TTP
candidates implied by the modeled topology, not proof that an attack occurred.
