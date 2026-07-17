# MITRE ATT&CK Technique Candidates

Generated deterministically from `system_model.json`. These are candidate TTP mappings, not evidence that an attack occurred.

Total ATT&CK findings: 12

| ID | Technique | Tactics | Title | Confidence |
| --- | --- | --- | --- | --- |
| `attack:t1078:attack-authenticated-entrypoint-valid-accounts:edge-actor-openapi-api-client-api-get-payments-paymentid-request:actor-openapi-api-client:api-get-payments-paymentid` | [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Defense Evasion, Persistence, Privilege Escalation, Initial Access | Valid-accounts abuse candidate for GET /payments/{paymentId} | medium |
| `attack:t1078:attack-authenticated-entrypoint-valid-accounts:edge-actor-openapi-api-client-api-post-payments-request:actor-openapi-api-client:api-post-payments` | [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Defense Evasion, Persistence, Privilege Escalation, Initial Access | Valid-accounts abuse candidate for POST /payments | medium |
| `attack:t1110:attack-authenticated-entrypoint-bruteforce:edge-actor-openapi-api-client-api-get-payments-paymentid-request:actor-openapi-api-client:api-get-payments-paymentid` | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | Credential Access | Brute-force technique candidate for GET /payments/{paymentId} | medium |
| `attack:t1110:attack-authenticated-entrypoint-bruteforce:edge-actor-openapi-api-client-api-post-payments-request:actor-openapi-api-client:api-post-payments` | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | Credential Access | Brute-force technique candidate for POST /payments | medium |
| `attack:t1190:attack-public-entrypoint:edge-actor-openapi-api-client-api-get-payments-paymentid-request:actor-openapi-api-client:api-get-payments-paymentid` | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Initial Access | Public-facing application technique candidate for GET /payments/{paymentId} | medium |
| `attack:t1190:attack-public-entrypoint:edge-actor-openapi-api-client-api-post-payments-request:actor-openapi-api-client:api-post-payments` | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Initial Access | Public-facing application technique candidate for POST /payments | medium |
| `attack:t1190:attack-public-entrypoint:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public` | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Initial Access | Public-facing application technique candidate for payments-public-lb | high |
| `attack:t1499:attack-entrypoint-dos:edge-actor-openapi-api-client-api-get-payments-paymentid-request:actor-openapi-api-client:api-get-payments-paymentid` | [T1499 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/) | Impact | Endpoint denial-of-service technique candidate for GET /payments/{paymentId} | high |
| `attack:t1499:attack-entrypoint-dos:edge-actor-openapi-api-client-api-post-payments-request:actor-openapi-api-client:api-post-payments` | [T1499 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/) | Impact | Endpoint denial-of-service technique candidate for POST /payments | high |
| `attack:t1499:attack-entrypoint-dos:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public` | [T1499 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/) | Impact | Endpoint denial-of-service technique candidate for payments-public-lb | high |
| `attack:t1557:attack-entrypoint-aitm:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public` | [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) | Credential Access, Collection | Adversary-in-the-middle candidate for payments-public-lb | low |
| `attack:t1565:attack-stored-data-manipulation:edge-terraform-aws-lambda-function-api-terraform-aws-db-instance-payments-stores:terraform-aws-lambda-function-api:terraform-aws-db-instance-payments` | [T1565 Data Manipulation](https://attack.mitre.org/techniques/T1565/) | Impact | Data manipulation technique candidate for payments-db | medium |

## Valid-accounts abuse candidate for GET /payments/{paymentId}

- ID: `attack:t1078:attack-authenticated-entrypoint-valid-accounts:edge-actor-openapi-api-client-api-get-payments-paymentid-request:actor-openapi-api-client:api-get-payments-paymentid`
- Rule: `attack-authenticated-entrypoint-valid-accounts`
- Technique: [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- Tactics: Defense Evasion, Persistence, Privilege Escalation, Initial Access
- Matrix: Enterprise ATT&CK
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`

Scenario: GET /payments/{paymentId} requires apiKey header:X-API-Key, but authorization requirements are not proven by the system model.

Detection: Monitor anomalous successful logins, privilege changes, impossible travel, and unusual API usage.

Mitigation: Enforce least privilege, MFA, session controls, and explicit per-operation authorization.

## Valid-accounts abuse candidate for POST /payments

- ID: `attack:t1078:attack-authenticated-entrypoint-valid-accounts:edge-actor-openapi-api-client-api-post-payments-request:actor-openapi-api-client:api-post-payments`
- Rule: `attack-authenticated-entrypoint-valid-accounts`
- Technique: [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- Tactics: Defense Evasion, Persistence, Privilege Escalation, Initial Access
- Matrix: Enterprise ATT&CK
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`

Scenario: POST /payments requires apiKey header:X-API-Key, but authorization requirements are not proven by the system model.

Detection: Monitor anomalous successful logins, privilege changes, impossible travel, and unusual API usage.

Mitigation: Enforce least privilege, MFA, session controls, and explicit per-operation authorization.

## Brute-force technique candidate for GET /payments/{paymentId}

- ID: `attack:t1110:attack-authenticated-entrypoint-bruteforce:edge-actor-openapi-api-client-api-get-payments-paymentid-request:actor-openapi-api-client:api-get-payments-paymentid`
- Rule: `attack-authenticated-entrypoint-bruteforce`
- Technique: [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)
- Tactics: Credential Access
- Matrix: Enterprise ATT&CK
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`

Scenario: GET /payments/{paymentId} has an authentication surface documented as apiKey header:X-API-Key, but abuse controls are not proven.

Detection: Monitor failed authentication bursts, source diversity, credential stuffing patterns, and lockouts.

Mitigation: Use MFA, throttling, lockouts, credential stuffing detection, and breached-password checks.

## Brute-force technique candidate for POST /payments

- ID: `attack:t1110:attack-authenticated-entrypoint-bruteforce:edge-actor-openapi-api-client-api-post-payments-request:actor-openapi-api-client:api-post-payments`
- Rule: `attack-authenticated-entrypoint-bruteforce`
- Technique: [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)
- Tactics: Credential Access
- Matrix: Enterprise ATT&CK
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`

Scenario: POST /payments has an authentication surface documented as apiKey header:X-API-Key, but abuse controls are not proven.

Detection: Monitor failed authentication bursts, source diversity, credential stuffing patterns, and lockouts.

Mitigation: Use MFA, throttling, lockouts, credential stuffing detection, and breached-password checks.

## Public-facing application technique candidate for GET /payments/{paymentId}

- ID: `attack:t1190:attack-public-entrypoint:edge-actor-openapi-api-client-api-get-payments-paymentid-request:actor-openapi-api-client:api-get-payments-paymentid`
- Rule: `attack-public-entrypoint`
- Technique: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- Tactics: Initial Access
- Matrix: Enterprise ATT&CK
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`

Scenario: GET /payments/{paymentId} is reachable from API Client. The model does not prove patching, WAF coverage, or exploit prevention controls.

Detection: Review web/API exploitation telemetry, WAF events, application errors, and ingress logs.

Mitigation: Patch exposed software, minimize exposed endpoints, validate inputs, and deploy WAF controls.

## Public-facing application technique candidate for POST /payments

- ID: `attack:t1190:attack-public-entrypoint:edge-actor-openapi-api-client-api-post-payments-request:actor-openapi-api-client:api-post-payments`
- Rule: `attack-public-entrypoint`
- Technique: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- Tactics: Initial Access
- Matrix: Enterprise ATT&CK
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`

Scenario: POST /payments is reachable from API Client. The model does not prove patching, WAF coverage, or exploit prevention controls.

Detection: Review web/API exploitation telemetry, WAF events, application errors, and ingress logs.

Mitigation: Patch exposed software, minimize exposed endpoints, validate inputs, and deploy WAF controls.

## Public-facing application technique candidate for payments-public-lb

- ID: `attack:t1190:attack-public-entrypoint:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public`
- Rule: `attack-public-entrypoint`
- Technique: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- Tactics: Initial Access
- Matrix: Enterprise ATT&CK
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`

Scenario: payments-public-lb is reachable from Internet. The model does not prove patching, WAF coverage, or exploit prevention controls.

Detection: Review web/API exploitation telemetry, WAF events, application errors, and ingress logs.

Mitigation: Patch exposed software, minimize exposed endpoints, validate inputs, and deploy WAF controls.

## Endpoint denial-of-service technique candidate for GET /payments/{paymentId}

- ID: `attack:t1499:attack-entrypoint-dos:edge-actor-openapi-api-client-api-get-payments-paymentid-request:actor-openapi-api-client:api-get-payments-paymentid`
- Rule: `attack-entrypoint-dos`
- Technique: [T1499 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- Tactics: Impact
- Matrix: Enterprise ATT&CK
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`

Scenario: GET /payments/{paymentId} receives traffic from API Client, and rate limiting or capacity controls are not proven in the model.

Detection: Monitor request rate, latency, error-rate spikes, queue depth, and saturation metrics.

Mitigation: Apply rate limits, request budgets, autoscaling, backpressure, and upstream filtering.

## Endpoint denial-of-service technique candidate for POST /payments

- ID: `attack:t1499:attack-entrypoint-dos:edge-actor-openapi-api-client-api-post-payments-request:actor-openapi-api-client:api-post-payments`
- Rule: `attack-entrypoint-dos`
- Technique: [T1499 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- Tactics: Impact
- Matrix: Enterprise ATT&CK
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`

Scenario: POST /payments receives traffic from API Client, and rate limiting or capacity controls are not proven in the model.

Detection: Monitor request rate, latency, error-rate spikes, queue depth, and saturation metrics.

Mitigation: Apply rate limits, request budgets, autoscaling, backpressure, and upstream filtering.

## Endpoint denial-of-service technique candidate for payments-public-lb

- ID: `attack:t1499:attack-entrypoint-dos:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public`
- Rule: `attack-entrypoint-dos`
- Technique: [T1499 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- Tactics: Impact
- Matrix: Enterprise ATT&CK
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`

Scenario: payments-public-lb receives traffic from Internet, and rate limiting or capacity controls are not proven in the model.

Detection: Monitor request rate, latency, error-rate spikes, queue depth, and saturation metrics.

Mitigation: Apply rate limits, request budgets, autoscaling, backpressure, and upstream filtering.

## Adversary-in-the-middle candidate for payments-public-lb

- ID: `attack:t1557:attack-entrypoint-aitm:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public`
- Rule: `attack-entrypoint-aitm`
- Technique: [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- Tactics: Credential Access, Collection
- Matrix: Enterprise ATT&CK
- Confidence: low
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`

Scenario: Transport protection for traffic from Internet to payments-public-lb is unknown in the system model.

Detection: Monitor TLS downgrade, certificate failures, unexpected proxies, and network path changes.

Mitigation: Require TLS, certificate validation, HSTS where applicable, and secure service-to-service channels.

## Data manipulation technique candidate for payments-db

- ID: `attack:t1565:attack-stored-data-manipulation:edge-terraform-aws-lambda-function-api-terraform-aws-db-instance-payments-stores:terraform-aws-lambda-function-api:terraform-aws-db-instance-payments`
- Rule: `attack-stored-data-manipulation`
- Technique: [T1565 Data Manipulation](https://attack.mitre.org/techniques/T1565/)
- Tactics: Impact
- Matrix: Enterprise ATT&CK
- Confidence: medium
- Status: candidate
- Affected elements: `edge:terraform-aws-lambda-function-api:terraform-aws-db-instance-payments:stores`, `terraform:aws-lambda-function:api`, `terraform:aws-db-instance:payments`

Scenario: payments-api stores or modifies data in payments-db. Integrity controls and recovery behavior are not proven.

Detection: Monitor unauthorized writes, abnormal update volume, integrity-check failures, and restore events.

Mitigation: Use least-privilege writes, validation, immutable audit logs, integrity checks, and backups.
