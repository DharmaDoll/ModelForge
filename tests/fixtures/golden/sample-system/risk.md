# Risk Priorities

Generated deterministically from `system_model.json`, STRIDE candidates, and MITRE ATT&CK candidates.

Total risk findings: 3

| ID | Rating | Score | Title |
| --- | --- | --- | --- |
| `risk:entrypoint:edge-actor-terraform-internet-terraform-aws-lb-public-public-access` | Low | 3 | Review priority for payments-public-lb entry point |
| `risk:entrypoint:edge-actor-openapi-api-client-api-get-payments-paymentid-request` | Low | 2 | Review priority for GET /payments/{paymentId} entry point |
| `risk:entrypoint:edge-actor-openapi-api-client-api-post-payments-request` | Low | 2 | Review priority for POST /payments entry point |

## Review priority for payments-public-lb entry point

- ID: `risk:entrypoint:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Rating: Low
- Score: 3
- Status: candidate
- Affected elements: `actor:terraform:internet`, `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `terraform:aws-lb:public`
- Related STRIDE threats: `threat:entrypoint-denial-of-service:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-elevation-of-privilege:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-information-disclosure:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-repudiation:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-spoofing:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-tampering:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Related ATT&CK findings: `attack:t1190:attack-public-entrypoint:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public`, `attack:t1499:attack-entrypoint-dos:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public`
- Derived from: `actor:terraform:internet`, `attack:t1190:attack-public-entrypoint:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public`, `attack:t1499:attack-entrypoint-dos:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public`, `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `terraform:aws-lb:public`, `threat:entrypoint-denial-of-service:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-elevation-of-privilege:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-information-disclosure:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-repudiation:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-spoofing:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`, `threat:entrypoint-tampering:edge-actor-terraform-internet-terraform-aws-lb-public-public-access`
- Evidence: `derived` (terraform/terraform, internet exposure); `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public")

Rationale:

- Entry point is public or internet-exposed.
- Authentication is unknown.
- Authorization requirements are unknown.
- Transport protection is unknown.
- Rate limiting or abuse controls are not proven.

## Review priority for GET /payments/{paymentId} entry point

- ID: `risk:entrypoint:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Rating: Low
- Score: 2
- Status: candidate
- Affected elements: `actor:openapi:api-client`, `api:get:payments-paymentid`, `data-asset:openapi:payment`, `edge:actor-openapi-api-client:api-get-payments-paymentid:request`
- Related STRIDE threats: `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-information-disclosure:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-spoofing:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Related ATT&CK findings: none
- Derived from: `actor:openapi:api-client`, `api:get:payments-paymentid`, `data-asset:openapi:payment`, `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-information-disclosure:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-spoofing:edge-actor-openapi-api-client-api-get-payments-paymentid-request`, `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-get-payments-paymentid-request`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, GET /payments/{paymentId}); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, components.schemas.Payment)

Rationale:

- Authorization requirements are unknown.
- Flow references sensitive model element types: data_asset.
- Data classification is unknown for referenced data assets.
- Rate limiting or abuse controls are not proven.

## Review priority for POST /payments entry point

- ID: `risk:entrypoint:edge-actor-openapi-api-client-api-post-payments-request`
- Rating: Low
- Score: 2
- Status: candidate
- Affected elements: `actor:openapi:api-client`, `api:post:payments`, `data-asset:openapi:payment`, `data-asset:openapi:paymentrequest`, `edge:actor-openapi-api-client:api-post-payments:request`
- Related STRIDE threats: `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-information-disclosure:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-spoofing:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-post-payments-request`
- Related ATT&CK findings: none
- Derived from: `actor:openapi:api-client`, `api:post:payments`, `data-asset:openapi:payment`, `data-asset:openapi:paymentrequest`, `edge:actor-openapi-api-client:api-post-payments:request`, `threat:entrypoint-denial-of-service:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-elevation-of-privilege:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-information-disclosure:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-repudiation:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-spoofing:edge-actor-openapi-api-client-api-post-payments-request`, `threat:entrypoint-tampering:edge-actor-openapi-api-client-api-post-payments-request`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, POST /payments); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, components.schemas.Payment); +1 more

Rationale:

- Authorization requirements are unknown.
- Flow references sensitive model element types: data_asset.
- Data classification is unknown for referenced data assets.
- Rate limiting or abuse controls are not proven.
