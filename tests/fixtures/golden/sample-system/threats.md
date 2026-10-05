# Threats

Generated deterministically from `system_model.json`. Review before acceptance.

Total threats: 24

| ID | STRIDE | Title | Confidence |
| --- | --- | --- | --- |
| `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | Denial of Service | Denial of service risk on GET /payments/{paymentId} | medium |
| `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-post-payments-request` | Denial of Service | Denial of service risk on POST /payments | medium |
| `threat:entrypoint-denial-of-service:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | Denial of Service | Denial of service risk on payments-public-lb | medium |
| `threat:entrypoint-denial-of-service:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671` | Denial of Service | Denial of service risk on Payments Gateway | medium |
| `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | Elevation of Privilege | Authorization bypass risk on GET /payments/{paymentId} | medium |
| `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-post-payments-request` | Elevation of Privilege | Authorization bypass risk on POST /payments | medium |
| `threat:entrypoint-elevation-of-privilege:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | Elevation of Privilege | Authorization bypass risk on payments-public-lb | medium |
| `threat:entrypoint-elevation-of-privilege:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671` | Elevation of Privilege | Authorization bypass risk on Payments Gateway | medium |
| `threat:entrypoint-information-disclosure:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | Information Disclosure | Information disclosure risk on GET /payments/{paymentId} | high |
| `threat:entrypoint-information-disclosure:edge-actor-openapi-api-client-api-post-payments-request` | Information Disclosure | Information disclosure risk on POST /payments | high |
| `threat:entrypoint-information-disclosure:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | Information Disclosure | Information disclosure risk on payments-public-lb | medium |
| `threat:entrypoint-information-disclosure:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671` | Information Disclosure | Information disclosure risk on Payments Gateway | medium |
| `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | Repudiation | Repudiation risk for GET /payments/{paymentId} | medium |
| `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-post-payments-request` | Repudiation | Repudiation risk for POST /payments | medium |
| `threat:entrypoint-repudiation:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | Repudiation | Repudiation risk for payments-public-lb | medium |
| `threat:entrypoint-repudiation:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671` | Repudiation | Repudiation risk for Payments Gateway | medium |
| `threat:entrypoint-spoofing:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | Spoofing | Spoofing risk from API Client to GET /payments/{paymentId} | medium |
| `threat:entrypoint-spoofing:edge-actor-openapi-api-client-api-post-payments-request` | Spoofing | Spoofing risk from API Client to POST /payments | medium |
| `threat:entrypoint-spoofing:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | Spoofing | Spoofing risk from Internet to payments-public-lb | medium |
| `threat:entrypoint-spoofing:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671` | Spoofing | Spoofing risk from Web Client to Payments Gateway | medium |
| `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | Tampering | Request tampering risk on GET /payments/{paymentId} | medium |
| `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-post-payments-request` | Tampering | Request tampering risk on POST /payments | medium |
| `threat:entrypoint-tampering:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | Tampering | Request tampering risk on payments-public-lb | high |
| `threat:entrypoint-tampering:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671` | Tampering | Request tampering risk on Payments Gateway | medium |

## Denial of service risk on GET /payments/{paymentId}

- ID: `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Rule: `entrypoint-denial-of-service`
- STRIDE: Denial of Service
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Derived from: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, GET /payments/{paymentId}); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Scenario: GET /payments/{paymentId} receives requests from API Client, and rate limiting or capacity controls are not proven.

Impact: High request volume or expensive inputs may degrade availability.

Mitigation: Apply rate limits, request size limits, timeouts, backpressure, and capacity monitoring.

## Denial of service risk on POST /payments

- ID: `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-post-payments-request`
- Rule: `entrypoint-denial-of-service`
- STRIDE: Denial of Service
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Derived from: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, POST /payments); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Scenario: POST /payments receives requests from API Client, and rate limiting or capacity controls are not proven.

Impact: High request volume or expensive inputs may degrade availability.

Mitigation: Apply rate limits, request size limits, timeouts, backpressure, and capacity monitoring.

## Denial of service risk on payments-public-lb

- ID: `threat:entrypoint-denial-of-service:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Rule: `entrypoint-denial-of-service`
- STRIDE: Denial of Service
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Scenario: payments-public-lb receives requests from Internet, and rate limiting or capacity controls are not proven.

Impact: High request volume or expensive inputs may degrade availability.

Mitigation: Apply rate limits, request size limits, timeouts, backpressure, and capacity monitoring.

## Denial of service risk on Payments Gateway

- ID: `threat:entrypoint-denial-of-service:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671`
- Rule: `entrypoint-denial-of-service`
- STRIDE: Denial of Service
- Confidence: medium
- Status: candidate
- Affected elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Derived from: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:5` (mermaid/markdown, mermaid block 1, line 2); `tests/fixtures/sample-system/docs/architecture.md:7` (mermaid/markdown, mermaid block 1, line 4)

Scenario: Payments Gateway receives requests from Web Client, and rate limiting or capacity controls are not proven.

Impact: High request volume or expensive inputs may degrade availability.

Mitigation: Apply rate limits, request size limits, timeouts, backpressure, and capacity monitoring.

## Authorization bypass risk on GET /payments/{paymentId}

- ID: `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Rule: `entrypoint-elevation-of-privilege`
- STRIDE: Elevation of Privilege
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Derived from: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, GET /payments/{paymentId}); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Scenario: Authorization requirements for this flow are not fully proven by the system model.

Impact: A caller may perform actions outside their intended privilege level.

Mitigation: Define authorization rules per operation and enforce them server-side with deny-by-default behavior.

## Authorization bypass risk on POST /payments

- ID: `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-post-payments-request`
- Rule: `entrypoint-elevation-of-privilege`
- STRIDE: Elevation of Privilege
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Derived from: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, POST /payments); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Scenario: Authorization requirements for this flow are not fully proven by the system model.

Impact: A caller may perform actions outside their intended privilege level.

Mitigation: Define authorization rules per operation and enforce them server-side with deny-by-default behavior.

## Authorization bypass risk on payments-public-lb

- ID: `threat:entrypoint-elevation-of-privilege:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Rule: `entrypoint-elevation-of-privilege`
- STRIDE: Elevation of Privilege
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Scenario: Authorization requirements for this flow are not fully proven by the system model.

Impact: A caller may perform actions outside their intended privilege level.

Mitigation: Define authorization rules per operation and enforce them server-side with deny-by-default behavior.

## Authorization bypass risk on Payments Gateway

- ID: `threat:entrypoint-elevation-of-privilege:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671`
- Rule: `entrypoint-elevation-of-privilege`
- STRIDE: Elevation of Privilege
- Confidence: medium
- Status: candidate
- Affected elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Derived from: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:5` (mermaid/markdown, mermaid block 1, line 2); `tests/fixtures/sample-system/docs/architecture.md:7` (mermaid/markdown, mermaid block 1, line 4)

Scenario: Authorization requirements for this flow are not fully proven by the system model.

Impact: A caller may perform actions outside their intended privilege level.

Mitigation: Define authorization rules per operation and enforce them server-side with deny-by-default behavior.

## Information disclosure risk on GET /payments/{paymentId}

- ID: `threat:entrypoint-information-disclosure:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Rule: `entrypoint-information-disclosure`
- STRIDE: Information Disclosure
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Derived from: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, GET /payments/{paymentId}); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Scenario: The flow may expose response data, and transport or data classification details are incomplete.

Impact: Sensitive data could be disclosed to unauthorized callers or over an unprotected channel.

Mitigation: Use TLS, minimize responses, classify referenced data assets, and enforce authorization before disclosure.

## Information disclosure risk on POST /payments

- ID: `threat:entrypoint-information-disclosure:edge-actor-openapi-api-client-api-post-payments-request`
- Rule: `entrypoint-information-disclosure`
- STRIDE: Information Disclosure
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Derived from: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, POST /payments); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Scenario: The flow may expose response data, and transport or data classification details are incomplete.

Impact: Sensitive data could be disclosed to unauthorized callers or over an unprotected channel.

Mitigation: Use TLS, minimize responses, classify referenced data assets, and enforce authorization before disclosure.

## Information disclosure risk on payments-public-lb

- ID: `threat:entrypoint-information-disclosure:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Rule: `entrypoint-information-disclosure`
- STRIDE: Information Disclosure
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Scenario: The flow may expose response data, and transport or data classification details are incomplete.

Impact: Sensitive data could be disclosed to unauthorized callers or over an unprotected channel.

Mitigation: Use TLS, minimize responses, classify referenced data assets, and enforce authorization before disclosure.

## Information disclosure risk on Payments Gateway

- ID: `threat:entrypoint-information-disclosure:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671`
- Rule: `entrypoint-information-disclosure`
- STRIDE: Information Disclosure
- Confidence: medium
- Status: candidate
- Affected elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Derived from: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:5` (mermaid/markdown, mermaid block 1, line 2); `tests/fixtures/sample-system/docs/architecture.md:7` (mermaid/markdown, mermaid block 1, line 4)

Scenario: The flow may expose response data, and transport or data classification details are incomplete.

Impact: Sensitive data could be disclosed to unauthorized callers or over an unprotected channel.

Mitigation: Use TLS, minimize responses, classify referenced data assets, and enforce authorization before disclosure.

## Repudiation risk for GET /payments/{paymentId}

- ID: `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Rule: `entrypoint-repudiation`
- STRIDE: Repudiation
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Derived from: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, GET /payments/{paymentId}); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Scenario: Audit logging for this externally reachable flow is not proven by the system model.

Impact: Security-relevant actions may be difficult to investigate or attribute after an incident.

Mitigation: Record authenticated principal, request metadata, decision outcomes, and tamper-resistant audit logs.

## Repudiation risk for POST /payments

- ID: `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-post-payments-request`
- Rule: `entrypoint-repudiation`
- STRIDE: Repudiation
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Derived from: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, POST /payments); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Scenario: Audit logging for this externally reachable flow is not proven by the system model.

Impact: Security-relevant actions may be difficult to investigate or attribute after an incident.

Mitigation: Record authenticated principal, request metadata, decision outcomes, and tamper-resistant audit logs.

## Repudiation risk for payments-public-lb

- ID: `threat:entrypoint-repudiation:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Rule: `entrypoint-repudiation`
- STRIDE: Repudiation
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Scenario: Audit logging for this externally reachable flow is not proven by the system model.

Impact: Security-relevant actions may be difficult to investigate or attribute after an incident.

Mitigation: Record authenticated principal, request metadata, decision outcomes, and tamper-resistant audit logs.

## Repudiation risk for Payments Gateway

- ID: `threat:entrypoint-repudiation:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671`
- Rule: `entrypoint-repudiation`
- STRIDE: Repudiation
- Confidence: medium
- Status: candidate
- Affected elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Derived from: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:5` (mermaid/markdown, mermaid block 1, line 2); `tests/fixtures/sample-system/docs/architecture.md:7` (mermaid/markdown, mermaid block 1, line 4)

Scenario: Audit logging for this externally reachable flow is not proven by the system model.

Impact: Security-relevant actions may be difficult to investigate or attribute after an incident.

Mitigation: Record authenticated principal, request metadata, decision outcomes, and tamper-resistant audit logs.

## Spoofing risk from API Client to GET /payments/{paymentId}

- ID: `threat:entrypoint-spoofing:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Rule: `entrypoint-spoofing`
- STRIDE: Spoofing
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Derived from: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, GET /payments/{paymentId}); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Scenario: Authentication is documented as apiKey header:X-API-Key. A caller may impersonate another principal when reaching GET /payments/{paymentId}.

Impact: Unauthorized access to exposed API behavior may occur if caller identity is weak or absent.

Mitigation: Require explicit authentication, validate credentials server-side, and document anonymous access if intentional.

## Spoofing risk from API Client to POST /payments

- ID: `threat:entrypoint-spoofing:edge-actor-openapi-api-client-api-post-payments-request`
- Rule: `entrypoint-spoofing`
- STRIDE: Spoofing
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Derived from: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, POST /payments); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Scenario: Authentication is documented as apiKey header:X-API-Key. A caller may impersonate another principal when reaching POST /payments.

Impact: Unauthorized access to exposed API behavior may occur if caller identity is weak or absent.

Mitigation: Require explicit authentication, validate credentials server-side, and document anonymous access if intentional.

## Spoofing risk from Internet to payments-public-lb

- ID: `threat:entrypoint-spoofing:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Rule: `entrypoint-spoofing`
- STRIDE: Spoofing
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Scenario: Authentication is not specified for this data flow. A caller may impersonate another principal when reaching payments-public-lb.

Impact: Unauthorized access to exposed API behavior may occur if caller identity is weak or absent.

Mitigation: Require explicit authentication, validate credentials server-side, and document anonymous access if intentional.

## Spoofing risk from Web Client to Payments Gateway

- ID: `threat:entrypoint-spoofing:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671`
- Rule: `entrypoint-spoofing`
- STRIDE: Spoofing
- Confidence: medium
- Status: candidate
- Affected elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Derived from: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:5` (mermaid/markdown, mermaid block 1, line 2); `tests/fixtures/sample-system/docs/architecture.md:7` (mermaid/markdown, mermaid block 1, line 4)

Scenario: Authentication is not specified for this data flow. A caller may impersonate another principal when reaching Payments Gateway.

Impact: Unauthorized access to exposed API behavior may occur if caller identity is weak or absent.

Mitigation: Require explicit authentication, validate credentials server-side, and document anonymous access if intentional.

## Request tampering risk on GET /payments/{paymentId}

- ID: `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Rule: `entrypoint-tampering`
- STRIDE: Tampering
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Derived from: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, GET /payments/{paymentId}); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Scenario: API Client sends input to GET /payments/{paymentId}. The model does not prove input integrity or validation.

Impact: Malformed or modified requests may change server-side state or bypass business rules.

Mitigation: Validate all inputs, enforce schema constraints, and use integrity protections where applicable.

## Request tampering risk on POST /payments

- ID: `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-post-payments-request`
- Rule: `entrypoint-tampering`
- STRIDE: Tampering
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Derived from: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, POST /payments); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Scenario: API Client sends input to POST /payments. The model does not prove input integrity or validation.

Impact: Malformed or modified requests may change server-side state or bypass business rules.

Mitigation: Validate all inputs, enforce schema constraints, and use integrity protections where applicable.

## Request tampering risk on payments-public-lb

- ID: `threat:entrypoint-tampering:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Rule: `entrypoint-tampering`
- STRIDE: Tampering
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Scenario: This flow crosses a trust boundary. Internet sends input to payments-public-lb. The model does not prove input integrity or validation.

Impact: Malformed or modified requests may change server-side state or bypass business rules.

Mitigation: Validate all inputs, enforce schema constraints, and use integrity protections where applicable.

## Request tampering risk on Payments Gateway

- ID: `threat:entrypoint-tampering:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671`
- Rule: `entrypoint-tampering`
- STRIDE: Tampering
- Confidence: medium
- Status: candidate
- Affected elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Derived from: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:5` (mermaid/markdown, mermaid block 1, line 2); `tests/fixtures/sample-system/docs/architecture.md:7` (mermaid/markdown, mermaid block 1, line 4)

Scenario: Web Client sends input to Payments Gateway. The model does not prove input integrity or validation.

Impact: Malformed or modified requests may change server-side state or bypass business rules.

Mitigation: Validate all inputs, enforce schema constraints, and use integrity protections where applicable.
