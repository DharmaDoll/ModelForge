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
* `questions.md`

## Usage

```bash
tm-ai analyze ./examples/sample-system \
  --readme ./examples/sample-system/README.md \
  --openapi ./examples/sample-system/openapi.yaml \
  --terraform ./examples/sample-system/main.tf \
  --out ./out
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
