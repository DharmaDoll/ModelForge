# ThreatModel-AI Development Guide

## Project Vision

Threat modeling today is largely a manual process that depends on experienced security engineers.

This project aims to transform threat modeling into an engineering discipline that can be continuously executed throughout the software development lifecycle.

The objective is **not** to replace security engineers.

The objective is to automatically generate a high-quality draft that security engineers can efficiently review and refine.

Ultimately, this project should enable **Continuous Threat Modeling**.

---

# Core Philosophy

The project follows several fundamental principles.

## 1. The Intermediate Model is the Source of Truth

The LLM is **never** the source of truth.

Instead, every input is normalized into a structured intermediate model.

```
Repository
OpenAPI
Terraform
README
Architecture Docs
        │
        ▼
Structured Extraction
        │
        ▼
system_model.json
        │
        ▼
DFD
        │
        ▼
STRIDE
        │
        ▼
Threat Report
```

Every module should consume and produce structured data whenever possible.

---

## 2. Deterministic Before Generative

Prefer deterministic implementations over LLM reasoning.

Examples:

Good

* OpenAPI parsing
* Terraform parsing
* JSON validation
* STRIDE rule engine

Bad

* Asking an LLM to "perform threat modeling"

LLMs should enhance deterministic outputs, not replace them.

---

## 3. No Hallucinations

Never invent architecture.

If information is unavailable:

* use `"unknown"`
* generate a clarification question
* never fabricate details

Unknown information is valuable.

---

## 4. Threat Modeling is a Graph Problem

Internally the system should be represented as a graph.

Nodes include:

* Actors
* Components
* APIs
* Databases
* External Services
* Secrets
* Data Assets
* Trust Boundaries

Edges include:

* communicates_with
* stores
* authenticates
* invokes
* owns

DFD is simply one visualization of this graph.

---

# MVP Scope

The first implementation should support only:

Input

* README
* OpenAPI
* Terraform

Output

* system_model.json
* dfd.mmd
* threats.md
* questions.md

No GUI is required.

CLI only.

---

# High-Level Architecture

```
              README
            OpenAPI
           Terraform
                │
                ▼
        Ingest Layer
                │
                ▼
     Structured Extractors
                │
                ▼
      system_model.json
                │
       ┌────────┼────────┐
       ▼        ▼        ▼
   DFD      STRIDE     Questions
Generator   Engine      Generator
       │        │        │
       └────────┼────────┘
                ▼
         Markdown Report
```

---

# Repository Layout

```
threatmodel_ai/

    ingest/
    extract/
    model/
    graph/
    dfd/
    stride/
    llm/
    report/
    cli/
    tests/
```

Keep responsibilities small.

One module should solve one problem.

---

# Intermediate Model

Everything revolves around one model.

```
system_model.json
```

Every extractor writes into it.

Every generator reads from it.

Never generate reports directly from raw files.

---

# LLM Usage Policy

LLMs are allowed only for:

* extracting structured information
* refining descriptions
* writing documentation
* generating clarification questions

LLMs must never:

* invent architecture
* assume authentication
* infer trust boundaries without evidence
* create components that do not exist

---

# STRIDE Engine

Threat generation should primarily be rule-based.

Rules should be deterministic.

Example:

External User

↓

REST API

Automatically evaluates

* Spoofing
* Tampering
* Repudiation
* Information Disclosure
* Denial of Service
* Elevation of Privilege

The LLM should improve descriptions—not decide whether a threat exists.

---

# DFD Generation

DFD is a generated artifact.

It is never manually maintained.

Preferred output:

Mermaid

Future support:

* OWASP Threat Dragon
* draw.io
* PlantUML

---

# Unknowns

Unknown information is not an error.

Unknowns should become review questions.

Example

```
Authentication method is unknown.

↓

Question:

How is this endpoint authenticated?
```

This is expected behavior.

---

# Coding Standards

Use:

* Python 3.12+
* Pydantic
* Typer
* Ruff
* Pytest

Requirements

* Strong typing
* Small functions
* Comprehensive docstrings
* Unit tests
* No duplicated logic

---

# Testing Strategy

Every module should be independently testable.

Never require an LLM for unit tests.

Mock every LLM interaction.

Golden test cases should verify:

* Mermaid generation
* STRIDE generation
* JSON schemas
* Markdown reports

---

# Security Requirements

This project may process confidential architecture.

Therefore:

* Do not log sensitive files.
* Do not print source code.
* Do not send files to external APIs unless explicitly enabled.
* External LLM usage must be opt-in.

---

# Future Vision

The MVP is only the beginning.

Future capabilities include:

* Kubernetes ingestion
* AWS Config ingestion
* Azure Resource Graph
* GCP Asset Inventory
* Runtime topology
* OpenTelemetry
* eBPF
* SBOM ingestion
* GitHub Actions integration
* Pull Request comments
* Jira integration
* Risk scoring
* Continuous Threat Modeling

---

# Development Priorities

Always prioritize work in the following order.

1. Intermediate Model
2. Validation
3. DFD Generation
4. STRIDE Engine
5. Report Generation
6. LLM Enhancement
7. CI/CD Integration
8. Cloud Integrations

---

# Definition of Done

A feature is complete only if:

* It includes unit tests.
* It updates the intermediate model correctly.
* It does not break CLI output.
* It works without an LLM.
* It produces deterministic output whenever possible.
* Documentation is updated.

---

# Final Principle

The goal of this project is **not to build another AI wrapper**.

The goal is to build an **AI-native Threat Modeling Platform** whose foundation is a structured system model, deterministic security reasoning, and optional LLM augmentation.

If a future contributor is unsure how to implement a feature, they should always ask:

> "Does this improve the quality of the intermediate model?"

If the answer is yes, it is likely the right direction.
