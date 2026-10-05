# Questions

Questions generated from unknown or incomplete model facts.

Total questions: 45

| ID | Category | Question |
| --- | --- | --- |
| `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:authentication` | authentication | How is payments-public-lb authenticated when called by Internet? |
| `question:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671:authentication` | authentication | How is Payments Gateway authenticated when called by Web Client? |
| `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-cd0f77eb37` | authentication | How is authentication implemented? |
| `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-d68eb436ec` | authentication | How is authentication implemented? |
| `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-f115e8104e` | authentication | How is authentication implemented? |
| `question:unknown-readme-authentication` | authentication | How is authentication implemented for Sample Payments API? |
| `question:unknown-terraform-terraform-aws-lb-public-authentication` | authentication | How is authentication implemented for payments-public-lb? |
| `question:edge-actor-openapi-api-client-api-get-payments-paymentid-request:authorization` | authorization | What authorization checks protect GET /payments/{paymentId}? |
| `question:edge-actor-openapi-api-client-api-post-payments-request:authorization` | authorization | What authorization checks protect POST /payments? |
| `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:authorization` | authorization | What authorization checks protect payments-public-lb? |
| `question:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671:authorization` | authorization | What authorization checks protect Payments Gateway? |
| `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-82286f0f84` | authorization | What authorization rules are enforced? |
| `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-99373844a4` | authorization | What authorization rules are enforced? |
| `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-9cbfb24442` | authorization | What authorization rules are enforced? |
| `question:unknown-openapi-api-get-payments-paymentid-authorization` | authorization | What authorization rules are enforced? |
| `question:unknown-openapi-api-post-payments-authorization` | authorization | What authorization rules are enforced? |
| `question:unknown-readme-authorization` | authorization | What authorization rules are enforced for Sample Payments API? |
| `question:data-asset-openapi-payment:data-classification` | data_classification | What is the data classification for Payment? |
| `question:data-asset-openapi-paymentrequest:data-classification` | data_classification | What is the data classification for PaymentRequest? |
| `question:unknown-openapi-payment-data-classification` | data_classification | What is the data classification for Payment? |
| `question:unknown-openapi-paymentrequest-data-classification` | data_classification | What is the data classification for PaymentRequest? |
| `question:data-asset-openapi-payment:encryption` | encryption | What encryption and access controls protect Payment? |
| `question:data-asset-openapi-paymentrequest:encryption` | encryption | What encryption and access controls protect PaymentRequest? |
| `question:database-readme-payments-db:encryption` | encryption | What encryption and access controls protect Payments DB? |
| `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:encryption` | encryption | Is traffic from Internet to payments-public-lb protected with TLS? |
| `question:terraform-aws-db-instance-payments:encryption` | encryption | What encryption and access controls protect payments-db? |
| `question:unknown-readme-encryption` | encryption | What encryption is used in transit and at rest for Sample Payments API? |
| `question:unknown-terraform-terraform-aws-db-instance-payments-encryption` | encryption | What encryption is used in transit and at rest for payments-db? |
| `question:unknown-readme-logging` | logging | What security-relevant events are logged for Sample Payments API? |
| `question:edge-actor-openapi-api-client-api-get-payments-paymentid-request:logging-monitoring` | logging_monitoring | What logging and monitoring exists for GET /payments/{paymentId}? |
| `question:edge-actor-openapi-api-client-api-post-payments-request:logging-monitoring` | logging_monitoring | What logging and monitoring exists for POST /payments? |
| `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:logging-monitoring` | logging_monitoring | What logging and monitoring exists for payments-public-lb? |
| `question:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671:logging-monitoring` | logging_monitoring | What logging and monitoring exists for Payments Gateway? |
| `question:unknown-readme-monitoring` | monitoring | What monitoring and alerting exists for Sample Payments API? |
| `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-2bf7321cc3` | protocol | What is the missing protocol detail? |
| `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-b7412ee742` | protocol | What is the missing protocol detail? |
| `question:edge-actor-openapi-api-client-api-get-payments-paymentid-request:rate-limiting` | rate_limiting | What rate limits protect GET /payments/{paymentId}? |
| `question:edge-actor-openapi-api-client-api-post-payments-request:rate-limiting` | rate_limiting | What rate limits protect POST /payments? |
| `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:rate-limiting` | rate_limiting | What rate limits protect payments-public-lb? |
| `question:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671:rate-limiting` | rate_limiting | What rate limits protect Payments Gateway? |
| `question:unknown-readme-rate-limiting` | rate_limiting | What rate limits or abuse controls are enforced for Sample Payments API? |
| `question:unknown-terraform-terraform-aws-lb-public-rate-limiting` | rate_limiting | What rate limits or abuse controls are enforced for payments-public-lb? |
| `question:edge-actor-openapi-api-client-api-get-payments-paymentid-request:trust-boundary` | trust_boundary | Which trust boundary contains GET /payments/{paymentId}? |
| `question:edge-actor-openapi-api-client-api-post-payments-request:trust-boundary` | trust_boundary | Which trust boundary contains POST /payments? |
| `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:trust-boundary` | trust_boundary | Which trust boundary contains payments-public-lb? |

## How is payments-public-lb authenticated when called by Internet?

- ID: `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:authentication`
- Category: authentication
- Related elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Rationale: Authentication is unknown for this external entry point.

## How is Payments Gateway authenticated when called by Web Client?

- ID: `question:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671:authentication`
- Category: authentication
- Related elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Derived from: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:5` (mermaid/markdown, mermaid block 1, line 2); `tests/fixtures/sample-system/docs/architecture.md:7` (mermaid/markdown, mermaid block 1, line 4)

Rationale: Authentication is unknown for this external entry point.

## How is authentication implemented?

- ID: `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-cd0f77eb37`
- Category: authentication
- Related elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-processor-b74d0d4b:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-store-0d8a7046:mermaid:9fc9265cbb`
- Derived from: `unknown:mermaid:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-process-0f9d98a5e7:authentication`, `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-processor-b74d0d4b:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-store-0d8a7046:mermaid:9fc9265cbb`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:8` (mermaid/markdown, mermaid block 1, line 5)

Rationale: Authentication for Mermaid flow Processor to Payment Store is unknown.

## How is authentication implemented?

- ID: `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-d68eb436ec`
- Category: authentication
- Related elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-processor-b74d0d4b:mermaid:9fc9265cbb`
- Derived from: `unknown:mermaid:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-fdffe1fe54:authentication`, `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-processor-b74d0d4b:mermaid:9fc9265cbb`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:7` (mermaid/markdown, mermaid block 1, line 4)

Rationale: Authentication for Mermaid flow Gateway to Payment Processor is unknown.

## How is authentication implemented?

- ID: `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-f115e8104e`
- Category: authentication
- Related elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`
- Derived from: `unknown:mermaid:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671:authentication`, `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:5` (mermaid/markdown, mermaid block 1, line 2)

Rationale: Authentication for Mermaid flow Web Client to Payments Gateway is unknown.

## How is authentication implemented for Sample Payments API?

- ID: `question:unknown-readme-authentication`
- Category: authentication
- Related elements: `component:readme:sample-payments-api`
- Derived from: `unknown:readme:authentication`, `component:readme:sample-payments-api`
- Evidence: `tests/fixtures/sample-system/README.md` (readme/readme, README)

Rationale: Authentication behavior is not described in the README.

## How is authentication implemented for payments-public-lb?

- ID: `question:unknown-terraform-terraform-aws-lb-public-authentication`
- Category: authentication
- Related elements: `terraform:aws-lb:public`
- Derived from: `unknown:terraform:terraform-aws-lb-public:authentication`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public")

Rationale: Authentication for internet-exposed resource payments-public-lb is unknown.

## What authorization checks protect GET /payments/{paymentId}?

- ID: `question:edge-actor-openapi-api-client-api-get-payments-paymentid-request:authorization`
- Category: authorization
- Related elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Derived from: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, GET /payments/{paymentId}); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Rationale: Authorization is unknown for this external entry point.

## What authorization checks protect POST /payments?

- ID: `question:edge-actor-openapi-api-client-api-post-payments-request:authorization`
- Category: authorization
- Related elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Derived from: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, POST /payments); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Rationale: Authorization is unknown for this external entry point.

## What authorization checks protect payments-public-lb?

- ID: `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:authorization`
- Category: authorization
- Related elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Rationale: Authorization is unknown for this external entry point.

## What authorization checks protect Payments Gateway?

- ID: `question:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671:authorization`
- Category: authorization
- Related elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Derived from: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:5` (mermaid/markdown, mermaid block 1, line 2); `tests/fixtures/sample-system/docs/architecture.md:7` (mermaid/markdown, mermaid block 1, line 4)

Rationale: Authorization is unknown for this external entry point.

## What authorization rules are enforced?

- ID: `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-82286f0f84`
- Category: authorization
- Related elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`
- Derived from: `unknown:mermaid:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671:authorization`, `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:5` (mermaid/markdown, mermaid block 1, line 2)

Rationale: Authorization for Mermaid flow Web Client to Payments Gateway is unknown.

## What authorization rules are enforced?

- ID: `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-99373844a4`
- Category: authorization
- Related elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-processor-b74d0d4b:mermaid:9fc9265cbb`
- Derived from: `unknown:mermaid:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-fdffe1fe54:authorization`, `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-processor-b74d0d4b:mermaid:9fc9265cbb`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:7` (mermaid/markdown, mermaid block 1, line 4)

Rationale: Authorization for Mermaid flow Gateway to Payment Processor is unknown.

## What authorization rules are enforced?

- ID: `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-9cbfb24442`
- Category: authorization
- Related elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-processor-b74d0d4b:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-store-0d8a7046:mermaid:9fc9265cbb`
- Derived from: `unknown:mermaid:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-process-0f9d98a5e7:authorization`, `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-processor-b74d0d4b:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-store-0d8a7046:mermaid:9fc9265cbb`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:8` (mermaid/markdown, mermaid block 1, line 5)

Rationale: Authorization for Mermaid flow Processor to Payment Store is unknown.

## What authorization rules are enforced?

- ID: `question:unknown-openapi-api-get-payments-paymentid-authorization`
- Category: authorization
- Related elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`
- Derived from: `unknown:openapi:api-get-payments-paymentid:authorization`, `edge:actor-openapi-api-client:api-get-payments-paymentid:request`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, GET /payments/{paymentId})

Rationale: Authorization requirements for GET /payments/{paymentId} are not specified.

## What authorization rules are enforced?

- ID: `question:unknown-openapi-api-post-payments-authorization`
- Category: authorization
- Related elements: `edge:actor-openapi-api-client:api-post-payments:request`
- Derived from: `unknown:openapi:api-post-payments:authorization`, `edge:actor-openapi-api-client:api-post-payments:request`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, POST /payments)

Rationale: Authorization requirements for POST /payments are not specified.

## What authorization rules are enforced for Sample Payments API?

- ID: `question:unknown-readme-authorization`
- Category: authorization
- Related elements: `component:readme:sample-payments-api`
- Derived from: `unknown:readme:authorization`, `component:readme:sample-payments-api`
- Evidence: `tests/fixtures/sample-system/README.md` (readme/readme, README)

Rationale: Authorization behavior is not described in the README.

## What is the data classification for Payment?

- ID: `question:data-asset-openapi-payment:data-classification`
- Category: data_classification
- Related elements: `data-asset:openapi:payment`
- Derived from: `data-asset:openapi:payment`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, components.schemas.Payment)

Rationale: Data asset classification is not present in the model.

## What is the data classification for PaymentRequest?

- ID: `question:data-asset-openapi-paymentrequest:data-classification`
- Category: data_classification
- Related elements: `data-asset:openapi:paymentrequest`
- Derived from: `data-asset:openapi:paymentrequest`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, components.schemas.PaymentRequest)

Rationale: Data asset classification is not present in the model.

## What is the data classification for Payment?

- ID: `question:unknown-openapi-payment-data-classification`
- Category: data_classification
- Related elements: `data-asset:openapi:payment`
- Derived from: `unknown:openapi:payment:data-classification`, `data-asset:openapi:payment`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, components.schemas.Payment)

Rationale: Data classification for schema Payment is unknown.

## What is the data classification for PaymentRequest?

- ID: `question:unknown-openapi-paymentrequest-data-classification`
- Category: data_classification
- Related elements: `data-asset:openapi:paymentrequest`
- Derived from: `unknown:openapi:paymentrequest:data-classification`, `data-asset:openapi:paymentrequest`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, components.schemas.PaymentRequest)

Rationale: Data classification for schema PaymentRequest is unknown.

## What encryption and access controls protect Payment?

- ID: `question:data-asset-openapi-payment:encryption`
- Category: encryption
- Related elements: `data-asset:openapi:payment`
- Derived from: `data-asset:openapi:payment`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, components.schemas.Payment)

Rationale: Storage protection details are not present in the model.

## What encryption and access controls protect PaymentRequest?

- ID: `question:data-asset-openapi-paymentrequest:encryption`
- Category: encryption
- Related elements: `data-asset:openapi:paymentrequest`
- Derived from: `data-asset:openapi:paymentrequest`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, components.schemas.PaymentRequest)

Rationale: Storage protection details are not present in the model.

## What encryption and access controls protect Payments DB?

- ID: `question:database-readme-payments-db:encryption`
- Category: encryption
- Related elements: `database:readme:payments-db`
- Derived from: `database:readme:payments-db`
- Evidence: `tests/fixtures/sample-system/README.md:15` (readme/readme, README section: Databases)

Rationale: Storage protection details are not present in the model.

## Is traffic from Internet to payments-public-lb protected with TLS?

- ID: `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:encryption`
- Category: encryption
- Related elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Rationale: Transport protection is not proven by the model.

## What encryption and access controls protect payments-db?

- ID: `question:terraform-aws-db-instance-payments:encryption`
- Category: encryption
- Related elements: `terraform:aws-db-instance:payments`
- Derived from: `terraform:aws-db-instance:payments`
- Evidence: `tests/fixtures/sample-system/main.tf:10` (terraform/terraform, resource "aws_db_instance" "payments")

Rationale: Storage protection details are not present in the model.

## What encryption is used in transit and at rest for Sample Payments API?

- ID: `question:unknown-readme-encryption`
- Category: encryption
- Related elements: `component:readme:sample-payments-api`
- Derived from: `unknown:readme:encryption`, `component:readme:sample-payments-api`
- Evidence: `tests/fixtures/sample-system/README.md` (readme/readme, README)

Rationale: Transport or storage encryption is not described in the README.

## What encryption is used in transit and at rest for payments-db?

- ID: `question:unknown-terraform-terraform-aws-db-instance-payments-encryption`
- Category: encryption
- Related elements: `terraform:aws-db-instance:payments`
- Derived from: `unknown:terraform:terraform-aws-db-instance-payments:encryption`, `terraform:aws-db-instance:payments`
- Evidence: `tests/fixtures/sample-system/main.tf:10` (terraform/terraform, resource "aws_db_instance" "payments")

Rationale: Encryption configuration for payments-db is unknown.

## What security-relevant events are logged for Sample Payments API?

- ID: `question:unknown-readme-logging`
- Category: logging
- Related elements: `component:readme:sample-payments-api`
- Derived from: `unknown:readme:logging`, `component:readme:sample-payments-api`
- Evidence: `tests/fixtures/sample-system/README.md` (readme/readme, README)

Rationale: Logging or audit behavior is not described in the README.

## What logging and monitoring exists for GET /payments/{paymentId}?

- ID: `question:edge-actor-openapi-api-client-api-get-payments-paymentid-request:logging-monitoring`
- Category: logging_monitoring
- Related elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Derived from: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, GET /payments/{paymentId}); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Rationale: Audit logging and monitoring are not proven for this external entry point.

## What logging and monitoring exists for POST /payments?

- ID: `question:edge-actor-openapi-api-client-api-post-payments-request:logging-monitoring`
- Category: logging_monitoring
- Related elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Derived from: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, POST /payments); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Rationale: Audit logging and monitoring are not proven for this external entry point.

## What logging and monitoring exists for payments-public-lb?

- ID: `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:logging-monitoring`
- Category: logging_monitoring
- Related elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Rationale: Audit logging and monitoring are not proven for this external entry point.

## What logging and monitoring exists for Payments Gateway?

- ID: `question:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671:logging-monitoring`
- Category: logging_monitoring
- Related elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Derived from: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:5` (mermaid/markdown, mermaid block 1, line 2); `tests/fixtures/sample-system/docs/architecture.md:7` (mermaid/markdown, mermaid block 1, line 4)

Rationale: Audit logging and monitoring are not proven for this external entry point.

## What monitoring and alerting exists for Sample Payments API?

- ID: `question:unknown-readme-monitoring`
- Category: monitoring
- Related elements: `component:readme:sample-payments-api`
- Derived from: `unknown:readme:monitoring`, `component:readme:sample-payments-api`
- Evidence: `tests/fixtures/sample-system/README.md` (readme/readme, README)

Rationale: Monitoring behavior is not described in the README.

## What is the missing protocol detail?

- ID: `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-2bf7321cc3`
- Category: protocol
- Related elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-processor-b74d0d4b:mermaid:9fc9265cbb`
- Derived from: `unknown:mermaid:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-fdffe1fe54:protocol`, `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-processor-b74d0d4b:mermaid:9fc9265cbb`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:7` (mermaid/markdown, mermaid block 1, line 4)

Rationale: Protocol for Mermaid flow Gateway to Payment Processor is unknown.

## What is the missing protocol detail?

- ID: `question:unknown-mermaid-edge-mermaid-node-docs-architecture-md-f48b101bb900-d-b7412ee742`
- Category: protocol
- Related elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-processor-b74d0d4b:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-store-0d8a7046:mermaid:9fc9265cbb`
- Derived from: `unknown:mermaid:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-process-0f9d98a5e7:protocol`, `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-processor-b74d0d4b:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-store-0d8a7046:mermaid:9fc9265cbb`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:8` (mermaid/markdown, mermaid block 1, line 5)

Rationale: Protocol for Mermaid flow Processor to Payment Store is unknown.

## What rate limits protect GET /payments/{paymentId}?

- ID: `question:edge-actor-openapi-api-client-api-get-payments-paymentid-request:rate-limiting`
- Category: rate_limiting
- Related elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Derived from: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, GET /payments/{paymentId}); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Rationale: Rate limiting is not proven for this external entry point.

## What rate limits protect POST /payments?

- ID: `question:edge-actor-openapi-api-client-api-post-payments-request:rate-limiting`
- Category: rate_limiting
- Related elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Derived from: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, POST /payments); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Rationale: Rate limiting is not proven for this external entry point.

## What rate limits protect payments-public-lb?

- ID: `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:rate-limiting`
- Category: rate_limiting
- Related elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Rationale: Rate limiting is not proven for this external entry point.

## What rate limits protect Payments Gateway?

- ID: `question:edge-mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client--c8b7536671:rate-limiting`
- Category: rate_limiting
- Related elements: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Derived from: `edge:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-client-1bdd79b1:mermaid-node-docs-architecture-md-f48b101bb900-diagram-1-gateway-5a0e1818:mermaid:2a74d5a30a`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:client:1bdd79b1`, `mermaid:node:docs-architecture-md-f48b101bb900:diagram-1:gateway:5a0e1818`
- Evidence: `tests/fixtures/sample-system/docs/architecture.md:5` (mermaid/markdown, mermaid block 1, line 2); `tests/fixtures/sample-system/docs/architecture.md:7` (mermaid/markdown, mermaid block 1, line 4)

Rationale: Rate limiting is not proven for this external entry point.

## What rate limits or abuse controls are enforced for Sample Payments API?

- ID: `question:unknown-readme-rate-limiting`
- Category: rate_limiting
- Related elements: `component:readme:sample-payments-api`
- Derived from: `unknown:readme:rate-limiting`, `component:readme:sample-payments-api`
- Evidence: `tests/fixtures/sample-system/README.md` (readme/readme, README)

Rationale: Rate limiting behavior is not described in the README.

## What rate limits or abuse controls are enforced for payments-public-lb?

- ID: `question:unknown-terraform-terraform-aws-lb-public-rate-limiting`
- Category: rate_limiting
- Related elements: `terraform:aws-lb:public`
- Derived from: `unknown:terraform:terraform-aws-lb-public:rate-limiting`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public")

Rationale: Rate limiting for internet-exposed resource payments-public-lb is unknown.

## Which trust boundary contains GET /payments/{paymentId}?

- ID: `question:edge-actor-openapi-api-client-api-get-payments-paymentid-request:trust-boundary`
- Category: trust_boundary
- Related elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Derived from: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, GET /payments/{paymentId}); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Rationale: Trust boundary membership is not present for this external entry point.

## Which trust boundary contains POST /payments?

- ID: `question:edge-actor-openapi-api-client-api-post-payments-request:trust-boundary`
- Category: trust_boundary
- Related elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Derived from: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`
- Evidence: `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, POST /payments); `tests/fixtures/sample-system/openapi.yaml` (openapi/openapi, OpenAPI)

Rationale: Trust boundary membership is not present for this external entry point.

## Which trust boundary contains payments-public-lb?

- ID: `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:trust-boundary`
- Category: trust_boundary
- Related elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `tests/fixtures/sample-system/main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Rationale: Trust boundary membership is not present for this external entry point.
