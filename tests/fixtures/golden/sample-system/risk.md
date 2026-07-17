# Risk Priorities

Generated deterministically from `system_model.json`, STRIDE candidates, and MITRE ATT&CK candidates.

Total risk findings: 4

| ID | Rating | Score | Title |
| --- | --- | --- | --- |
| `risk:entrypoint:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | High | 8 | Review priority for GET /payments/{paymentId} entry point |
| `risk:entrypoint:edge-actor-openapi-api-client-api-post-payments-request` | High | 8 | Review priority for POST /payments entry point |
| `risk:entrypoint:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | High | 8 | Review priority for payments-public-lb entry point |
| `risk:storage:edge-terraform-aws-lambda-function-api-terraform-aws-db-instance-payments-stores` | Medium | 5 | Review priority for storage path to payments-db |

## Review priority for GET /payments/{paymentId} entry point

- ID: `risk:entrypoint:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Rating: High
- Score: 8
- Status: candidate
- Affected elements: `actor:openapi:api-client`, `api:get:payments-paymentid`, `data-asset:openapi:payment`, `edge:actor-openapi-api-client:api-get-payments-paymentid:request`
- Related STRIDE threats: `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-information-disclosure:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-spoofing:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Related ATT&CK findings: `attack:t1078:attack-authenticated-entrypoint-valid-accounts:edge-actor-openapi-api-client-api-get-payments-paymentid-request:actor-openapi-api-client:api-get-payments-paymentid`, `attack:t1110:attack-authenticated-entrypoint-bruteforce:edge-actor-openapi-api-client-api-get-payments-paymentid-request:actor-openapi-api-client:api-get-payments-paymentid`, `attack:t1190:attack-public-entrypoint:edge-actor-openapi-api-client-api-get-payments-paymentid-request:actor-openapi-api-client:api-get-payments-paymentid`, `attack:t1499:attack-entrypoint-dos:edge-actor-openapi-api-client-api-get-payments-paymentid-request:actor-openapi-api-client:api-get-payments-paymentid`

Rationale:

- Entry point is public or internet-exposed.
- Authorization requirements are unknown.
- Flow references sensitive model element types: data_asset.
- Data classification is unknown for referenced data assets.
- Rate limiting or abuse controls are not proven.

## Review priority for POST /payments entry point

- ID: `risk:entrypoint:edge-actor-openapi-api-client-api-post-payments-request`
- Rating: High
- Score: 8
- Status: candidate
- Affected elements: `actor:openapi:api-client`, `api:post:payments`, `data-asset:openapi:payment`, `data-asset:openapi:paymentrequest`, `edge:actor-openapi-api-client:api-post-payments:request`
- Related STRIDE threats: `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-information-disclosure:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-spoofing:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-post-payments-request`
- Related ATT&CK findings: `attack:t1078:attack-authenticated-entrypoint-valid-accounts:edge-actor-openapi-api-client-api-post-payments-request:actor-openapi-api-client:api-post-payments`, `attack:t1110:attack-authenticated-entrypoint-bruteforce:edge-actor-openapi-api-client-api-post-payments-request:actor-openapi-api-client:api-post-payments`, `attack:t1190:attack-public-entrypoint:edge-actor-openapi-api-client-api-post-payments-request:actor-openapi-api-client:api-post-payments`, `attack:t1499:attack-entrypoint-dos:edge-actor-openapi-api-client-api-post-payments-request:actor-openapi-api-client:api-post-payments`

Rationale:

- Entry point is public or internet-exposed.
- Authorization requirements are unknown.
- Flow references sensitive model element types: data_asset.
- Data classification is unknown for referenced data assets.
- Rate limiting or abuse controls are not proven.

## Review priority for payments-public-lb entry point

- ID: `risk:entrypoint:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Rating: High
- Score: 8
- Status: candidate
- Affected elements: `actor:terraform:internet`, `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `terraform:aws-lb:public`
- Related STRIDE threats: `threat:entrypoint-denial-of-service:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-elevation-of-privilege:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-information-disclosure:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-repudiation:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-spoofing:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-tampering:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Related ATT&CK findings: `attack:t1190:attack-public-entrypoint:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public`, `attack:t1499:attack-entrypoint-dos:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public`, `attack:t1557:attack-entrypoint-aitm:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public`

Rationale:

- Entry point is public or internet-exposed.
- Authentication is unknown.
- Authorization requirements are unknown.
- Transport protection is unknown.
- Rate limiting or abuse controls are not proven.

## Review priority for storage path to payments-db

- ID: `risk:storage:edge-terraform-aws-lambda-function-api-terraform-aws-db-instance-payments-stores`
- Rating: Medium
- Score: 5
- Status: candidate
- Affected elements: `edge:terraform-aws-lambda-function-api:terraform-aws-db-instance-payments:stores`, `terraform:aws-db-instance:payments`, `terraform:aws-lambda-function:api`
- Related STRIDE threats: `threat:store-information-disclosure:edge-terraform-aws-lambda-function-api-terraform-aws-db-instance-payments-stores`, `threat:store-tampering:edge-terraform-aws-lambda-function-api-terraform-aws-db-instance-payments-stores`
- Related ATT&CK findings: `attack:t1565:attack-stored-data-manipulation:edge-terraform-aws-lambda-function-api-terraform-aws-db-instance-payments-stores:terraform-aws-lambda-function-api:terraform-aws-db-instance-payments`

Rationale:

- Flow stores or modifies a modeled data asset.
- Target is a database.
- Data classification is unknown for the storage target.
