# Threats

Generated deterministically from `system_model.json`. Review before acceptance.

Total threats: 20

| ID | STRIDE | Title | Confidence |
| --- | --- | --- | --- |
| `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | Denial of Service | Denial of service risk on GET /payments/{paymentId} | high |
| `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-post-payments-request` | Denial of Service | Denial of service risk on POST /payments | high |
| `threat:entrypoint-denial-of-service:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | Denial of Service | Denial of service risk on payments-public-lb | high |
| `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | Elevation of Privilege | Authorization bypass risk on GET /payments/{paymentId} | high |
| `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-post-payments-request` | Elevation of Privilege | Authorization bypass risk on POST /payments | high |
| `threat:entrypoint-elevation-of-privilege:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | Elevation of Privilege | Authorization bypass risk on payments-public-lb | high |
| `threat:entrypoint-information-disclosure:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | Information Disclosure | Information disclosure risk on GET /payments/{paymentId} | high |
| `threat:entrypoint-information-disclosure:edge-actor-openapi-api-client-api-post-payments-request` | Information Disclosure | Information disclosure risk on POST /payments | high |
| `threat:entrypoint-information-disclosure:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | Information Disclosure | Information disclosure risk on payments-public-lb | high |
| `threat:store-information-disclosure:edge-terraform-aws-lambda-function-api-terraform-aws-db-instance-payments-stores` | Information Disclosure | Stored data disclosure risk in payments-db | medium |
| `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | Repudiation | Repudiation risk for GET /payments/{paymentId} | high |
| `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-post-payments-request` | Repudiation | Repudiation risk for POST /payments | high |
| `threat:entrypoint-repudiation:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | Repudiation | Repudiation risk for payments-public-lb | high |
| `threat:entrypoint-spoofing:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | Spoofing | Spoofing risk from API Client to GET /payments/{paymentId} | medium |
| `threat:entrypoint-spoofing:edge-actor-openapi-api-client-api-post-payments-request` | Spoofing | Spoofing risk from API Client to POST /payments | medium |
| `threat:entrypoint-spoofing:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | Spoofing | Spoofing risk from Internet to payments-public-lb | high |
| `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | Tampering | Request tampering risk on GET /payments/{paymentId} | high |
| `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-post-payments-request` | Tampering | Request tampering risk on POST /payments | high |
| `threat:entrypoint-tampering:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | Tampering | Request tampering risk on payments-public-lb | high |
| `threat:store-tampering:edge-terraform-aws-lambda-function-api-terraform-aws-db-instance-payments-stores` | Tampering | Stored data tampering risk in payments-db | medium |

## Denial of service risk on GET /payments/{paymentId}

- ID: `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Rule: `entrypoint-denial-of-service`
- STRIDE: Denial of Service
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`

Scenario: GET /payments/{paymentId} receives requests from API Client, and rate limiting or capacity controls are not proven.

Impact: High request volume or expensive inputs may degrade availability.

Mitigation: Apply rate limits, request size limits, timeouts, backpressure, and capacity monitoring.

## Denial of service risk on POST /payments

- ID: `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-post-payments-request`
- Rule: `entrypoint-denial-of-service`
- STRIDE: Denial of Service
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`

Scenario: POST /payments receives requests from API Client, and rate limiting or capacity controls are not proven.

Impact: High request volume or expensive inputs may degrade availability.

Mitigation: Apply rate limits, request size limits, timeouts, backpressure, and capacity monitoring.

## Denial of service risk on payments-public-lb

- ID: `threat:entrypoint-denial-of-service:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Rule: `entrypoint-denial-of-service`
- STRIDE: Denial of Service
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`

Scenario: payments-public-lb receives requests from Internet, and rate limiting or capacity controls are not proven.

Impact: High request volume or expensive inputs may degrade availability.

Mitigation: Apply rate limits, request size limits, timeouts, backpressure, and capacity monitoring.

## Authorization bypass risk on GET /payments/{paymentId}

- ID: `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Rule: `entrypoint-elevation-of-privilege`
- STRIDE: Elevation of Privilege
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`

Scenario: Authorization requirements for this flow are not fully proven by the system model.

Impact: A caller may perform actions outside their intended privilege level.

Mitigation: Define authorization rules per operation and enforce them server-side with deny-by-default behavior.

## Authorization bypass risk on POST /payments

- ID: `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-post-payments-request`
- Rule: `entrypoint-elevation-of-privilege`
- STRIDE: Elevation of Privilege
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`

Scenario: Authorization requirements for this flow are not fully proven by the system model.

Impact: A caller may perform actions outside their intended privilege level.

Mitigation: Define authorization rules per operation and enforce them server-side with deny-by-default behavior.

## Authorization bypass risk on payments-public-lb

- ID: `threat:entrypoint-elevation-of-privilege:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Rule: `entrypoint-elevation-of-privilege`
- STRIDE: Elevation of Privilege
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`

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

Scenario: The flow may expose response data, and transport or data classification details are incomplete.

Impact: Sensitive data could be disclosed to unauthorized callers or over an unprotected channel.

Mitigation: Use TLS, minimize responses, classify referenced data assets, and enforce authorization before disclosure.

## Information disclosure risk on payments-public-lb

- ID: `threat:entrypoint-information-disclosure:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Rule: `entrypoint-information-disclosure`
- STRIDE: Information Disclosure
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`

Scenario: The flow may expose response data, and transport or data classification details are incomplete.

Impact: Sensitive data could be disclosed to unauthorized callers or over an unprotected channel.

Mitigation: Use TLS, minimize responses, classify referenced data assets, and enforce authorization before disclosure.

## Stored data disclosure risk in payments-db

- ID: `threat:store-information-disclosure:edge-terraform-aws-lambda-function-api-terraform-aws-db-instance-payments-stores`
- Rule: `store-information-disclosure`
- STRIDE: Information Disclosure
- Confidence: medium
- Status: candidate
- Affected elements: `edge:terraform-aws-lambda-function-api:terraform-aws-db-instance-payments:stores`, `terraform:aws-lambda-function:api`, `terraform:aws-db-instance:payments`

Scenario: Encryption, access control, or data classification for this stored asset is not proven.

Impact: Stored sensitive data may be exposed if the backing service or credentials are compromised.

Mitigation: Classify the data, enforce least-privilege access, and enable encryption at rest.

## Repudiation risk for GET /payments/{paymentId}

- ID: `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Rule: `entrypoint-repudiation`
- STRIDE: Repudiation
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`

Scenario: Audit logging for this externally reachable flow is not proven by the system model.

Impact: Security-relevant actions may be difficult to investigate or attribute after an incident.

Mitigation: Record authenticated principal, request metadata, decision outcomes, and tamper-resistant audit logs.

## Repudiation risk for POST /payments

- ID: `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-post-payments-request`
- Rule: `entrypoint-repudiation`
- STRIDE: Repudiation
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`

Scenario: Audit logging for this externally reachable flow is not proven by the system model.

Impact: Security-relevant actions may be difficult to investigate or attribute after an incident.

Mitigation: Record authenticated principal, request metadata, decision outcomes, and tamper-resistant audit logs.

## Repudiation risk for payments-public-lb

- ID: `threat:entrypoint-repudiation:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Rule: `entrypoint-repudiation`
- STRIDE: Repudiation
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`

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

Scenario: Authentication is documented as apiKey header:X-API-Key. A caller may impersonate another principal when reaching POST /payments.

Impact: Unauthorized access to exposed API behavior may occur if caller identity is weak or absent.

Mitigation: Require explicit authentication, validate credentials server-side, and document anonymous access if intentional.

## Spoofing risk from Internet to payments-public-lb

- ID: `threat:entrypoint-spoofing:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Rule: `entrypoint-spoofing`
- STRIDE: Spoofing
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`

Scenario: Authentication is not specified for this data flow. A caller may impersonate another principal when reaching payments-public-lb.

Impact: Unauthorized access to exposed API behavior may occur if caller identity is weak or absent.

Mitigation: Require explicit authentication, validate credentials server-side, and document anonymous access if intentional.

## Request tampering risk on GET /payments/{paymentId}

- ID: `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Rule: `entrypoint-tampering`
- STRIDE: Tampering
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`

Scenario: API Client sends input to GET /payments/{paymentId}. The model does not prove input integrity or validation.

Impact: Malformed or modified requests may change server-side state or bypass business rules.

Mitigation: Validate all inputs, enforce schema constraints, and use integrity protections where applicable.

## Request tampering risk on POST /payments

- ID: `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-post-payments-request`
- Rule: `entrypoint-tampering`
- STRIDE: Tampering
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`

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

Scenario: Internet sends input to payments-public-lb. The model does not prove input integrity or validation.

Impact: Malformed or modified requests may change server-side state or bypass business rules.

Mitigation: Validate all inputs, enforce schema constraints, and use integrity protections where applicable.

## Stored data tampering risk in payments-db

- ID: `threat:store-tampering:edge-terraform-aws-lambda-function-api-terraform-aws-db-instance-payments-stores`
- Rule: `store-tampering`
- STRIDE: Tampering
- Confidence: medium
- Status: candidate
- Affected elements: `edge:terraform-aws-lambda-function-api:terraform-aws-db-instance-payments:stores`, `terraform:aws-lambda-function:api`, `terraform:aws-db-instance:payments`

Scenario: payments-api has a modelled storage relationship with payments-db.

Impact: Unauthorized writes or weak integrity controls may corrupt stored data.

Mitigation: Apply least-privilege write permissions, validation, integrity checks, and backups.
