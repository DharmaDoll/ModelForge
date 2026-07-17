# Questions

Questions generated from unknown or incomplete model facts.

Total questions: 38

| ID | Category | Question |
| --- | --- | --- |
| `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:authentication` | authentication | How is payments-public-lb authenticated when called by Internet? |
| `question:unknown-mermaid-edge-component-mermaid-client-component-mermaid-gatew-a43e456158` | authentication | How is authentication implemented? |
| `question:unknown-mermaid-edge-component-mermaid-gateway-component-mermaid-proc-70315ff90f` | authentication | How is authentication implemented? |
| `question:unknown-mermaid-edge-component-mermaid-processor-component-mermaid-st-033953d7c7` | authentication | How is authentication implemented? |
| `question:unknown-readme-authentication` | authentication | How is authentication implemented for Sample Payments API? |
| `question:unknown-terraform-terraform-aws-lb-public-authentication` | authentication | How is authentication implemented for payments-public-lb? |
| `question:edge-actor-openapi-api-client-api-get-payments-paymentid-request:authorization` | authorization | What authorization checks protect GET /payments/{paymentId}? |
| `question:edge-actor-openapi-api-client-api-post-payments-request:authorization` | authorization | What authorization checks protect POST /payments? |
| `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:authorization` | authorization | What authorization checks protect payments-public-lb? |
| `question:unknown-mermaid-edge-component-mermaid-client-component-mermaid-gatew-ece205ed39` | authorization | What authorization rules are enforced? |
| `question:unknown-mermaid-edge-component-mermaid-gateway-component-mermaid-proc-391731b442` | authorization | What authorization rules are enforced? |
| `question:unknown-mermaid-edge-component-mermaid-processor-component-mermaid-st-4e978dc9f6` | authorization | What authorization rules are enforced? |
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
| `question:unknown-readme-monitoring` | monitoring | What monitoring and alerting exists for Sample Payments API? |
| `question:unknown-mermaid-edge-component-mermaid-gateway-component-mermaid-proc-53d2409de0` | protocol | What is the missing protocol detail? |
| `question:unknown-mermaid-edge-component-mermaid-processor-component-mermaid-st-75e904e3ff` | protocol | What is the missing protocol detail? |
| `question:edge-actor-openapi-api-client-api-get-payments-paymentid-request:rate-limiting` | rate_limiting | What rate limits protect GET /payments/{paymentId}? |
| `question:edge-actor-openapi-api-client-api-post-payments-request:rate-limiting` | rate_limiting | What rate limits protect POST /payments? |
| `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:rate-limiting` | rate_limiting | What rate limits protect payments-public-lb? |
| `question:unknown-readme-rate-limiting` | rate_limiting | What rate limits or abuse controls are enforced for Sample Payments API? |
| `question:unknown-terraform-terraform-aws-lb-public-rate-limiting` | rate_limiting | What rate limits or abuse controls are enforced for payments-public-lb? |

## How is payments-public-lb authenticated when called by Internet?

- ID: `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:authentication`
- Category: authentication
- Related elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`

Rationale: Authentication is unknown for this external entry point.

## How is authentication implemented?

- ID: `question:unknown-mermaid-edge-component-mermaid-client-component-mermaid-gatew-a43e456158`
- Category: authentication
- Related elements: `edge:component-mermaid-client:component-mermaid-gateway:mermaid`

Rationale: Authentication for Mermaid flow Web Client to Payments Gateway is unknown.

## How is authentication implemented?

- ID: `question:unknown-mermaid-edge-component-mermaid-gateway-component-mermaid-proc-70315ff90f`
- Category: authentication
- Related elements: `edge:component-mermaid-gateway:component-mermaid-processor:mermaid`

Rationale: Authentication for Mermaid flow Gateway to Payment Processor is unknown.

## How is authentication implemented?

- ID: `question:unknown-mermaid-edge-component-mermaid-processor-component-mermaid-st-033953d7c7`
- Category: authentication
- Related elements: `edge:component-mermaid-processor:component-mermaid-store:mermaid`

Rationale: Authentication for Mermaid flow Processor to Payment Store is unknown.

## How is authentication implemented for Sample Payments API?

- ID: `question:unknown-readme-authentication`
- Category: authentication
- Related elements: `component:readme:sample-payments-api`

Rationale: Authentication behavior is not described in the README.

## How is authentication implemented for payments-public-lb?

- ID: `question:unknown-terraform-terraform-aws-lb-public-authentication`
- Category: authentication
- Related elements: `terraform:aws-lb:public`

Rationale: Authentication for internet-exposed resource payments-public-lb is unknown.

## What authorization checks protect GET /payments/{paymentId}?

- ID: `question:edge-actor-openapi-api-client-api-get-payments-paymentid-request:authorization`
- Category: authorization
- Related elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`

Rationale: Authorization is unknown for this external entry point.

## What authorization checks protect POST /payments?

- ID: `question:edge-actor-openapi-api-client-api-post-payments-request:authorization`
- Category: authorization
- Related elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`

Rationale: Authorization is unknown for this external entry point.

## What authorization checks protect payments-public-lb?

- ID: `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:authorization`
- Category: authorization
- Related elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`

Rationale: Authorization is unknown for this external entry point.

## What authorization rules are enforced?

- ID: `question:unknown-mermaid-edge-component-mermaid-client-component-mermaid-gatew-ece205ed39`
- Category: authorization
- Related elements: `edge:component-mermaid-client:component-mermaid-gateway:mermaid`

Rationale: Authorization for Mermaid flow Web Client to Payments Gateway is unknown.

## What authorization rules are enforced?

- ID: `question:unknown-mermaid-edge-component-mermaid-gateway-component-mermaid-proc-391731b442`
- Category: authorization
- Related elements: `edge:component-mermaid-gateway:component-mermaid-processor:mermaid`

Rationale: Authorization for Mermaid flow Gateway to Payment Processor is unknown.

## What authorization rules are enforced?

- ID: `question:unknown-mermaid-edge-component-mermaid-processor-component-mermaid-st-4e978dc9f6`
- Category: authorization
- Related elements: `edge:component-mermaid-processor:component-mermaid-store:mermaid`

Rationale: Authorization for Mermaid flow Processor to Payment Store is unknown.

## What authorization rules are enforced?

- ID: `question:unknown-openapi-api-get-payments-paymentid-authorization`
- Category: authorization
- Related elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`

Rationale: Authorization requirements for GET /payments/{paymentId} are not specified.

## What authorization rules are enforced?

- ID: `question:unknown-openapi-api-post-payments-authorization`
- Category: authorization
- Related elements: `edge:actor-openapi-api-client:api-post-payments:request`

Rationale: Authorization requirements for POST /payments are not specified.

## What authorization rules are enforced for Sample Payments API?

- ID: `question:unknown-readme-authorization`
- Category: authorization
- Related elements: `component:readme:sample-payments-api`

Rationale: Authorization behavior is not described in the README.

## What is the data classification for Payment?

- ID: `question:data-asset-openapi-payment:data-classification`
- Category: data_classification
- Related elements: `data-asset:openapi:payment`

Rationale: Data asset classification is not present in the model.

## What is the data classification for PaymentRequest?

- ID: `question:data-asset-openapi-paymentrequest:data-classification`
- Category: data_classification
- Related elements: `data-asset:openapi:paymentrequest`

Rationale: Data asset classification is not present in the model.

## What is the data classification for Payment?

- ID: `question:unknown-openapi-payment-data-classification`
- Category: data_classification
- Related elements: `data-asset:openapi:payment`

Rationale: Data classification for schema Payment is unknown.

## What is the data classification for PaymentRequest?

- ID: `question:unknown-openapi-paymentrequest-data-classification`
- Category: data_classification
- Related elements: `data-asset:openapi:paymentrequest`

Rationale: Data classification for schema PaymentRequest is unknown.

## What encryption and access controls protect Payment?

- ID: `question:data-asset-openapi-payment:encryption`
- Category: encryption
- Related elements: `data-asset:openapi:payment`

Rationale: Storage protection details are not present in the model.

## What encryption and access controls protect PaymentRequest?

- ID: `question:data-asset-openapi-paymentrequest:encryption`
- Category: encryption
- Related elements: `data-asset:openapi:paymentrequest`

Rationale: Storage protection details are not present in the model.

## What encryption and access controls protect Payments DB?

- ID: `question:database-readme-payments-db:encryption`
- Category: encryption
- Related elements: `database:readme:payments-db`

Rationale: Storage protection details are not present in the model.

## Is traffic from Internet to payments-public-lb protected with TLS?

- ID: `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:encryption`
- Category: encryption
- Related elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`

Rationale: Transport protection is not proven by the model.

## What encryption and access controls protect payments-db?

- ID: `question:terraform-aws-db-instance-payments:encryption`
- Category: encryption
- Related elements: `terraform:aws-db-instance:payments`

Rationale: Storage protection details are not present in the model.

## What encryption is used in transit and at rest for Sample Payments API?

- ID: `question:unknown-readme-encryption`
- Category: encryption
- Related elements: `component:readme:sample-payments-api`

Rationale: Transport or storage encryption is not described in the README.

## What encryption is used in transit and at rest for payments-db?

- ID: `question:unknown-terraform-terraform-aws-db-instance-payments-encryption`
- Category: encryption
- Related elements: `terraform:aws-db-instance:payments`

Rationale: Encryption configuration for payments-db is unknown.

## What security-relevant events are logged for Sample Payments API?

- ID: `question:unknown-readme-logging`
- Category: logging
- Related elements: `component:readme:sample-payments-api`

Rationale: Logging or audit behavior is not described in the README.

## What logging and monitoring exists for GET /payments/{paymentId}?

- ID: `question:edge-actor-openapi-api-client-api-get-payments-paymentid-request:logging-monitoring`
- Category: logging_monitoring
- Related elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`

Rationale: Audit logging and monitoring are not proven for this external entry point.

## What logging and monitoring exists for POST /payments?

- ID: `question:edge-actor-openapi-api-client-api-post-payments-request:logging-monitoring`
- Category: logging_monitoring
- Related elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`

Rationale: Audit logging and monitoring are not proven for this external entry point.

## What logging and monitoring exists for payments-public-lb?

- ID: `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:logging-monitoring`
- Category: logging_monitoring
- Related elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`

Rationale: Audit logging and monitoring are not proven for this external entry point.

## What monitoring and alerting exists for Sample Payments API?

- ID: `question:unknown-readme-monitoring`
- Category: monitoring
- Related elements: `component:readme:sample-payments-api`

Rationale: Monitoring behavior is not described in the README.

## What is the missing protocol detail?

- ID: `question:unknown-mermaid-edge-component-mermaid-gateway-component-mermaid-proc-53d2409de0`
- Category: protocol
- Related elements: `edge:component-mermaid-gateway:component-mermaid-processor:mermaid`

Rationale: Protocol for Mermaid flow Gateway to Payment Processor is unknown.

## What is the missing protocol detail?

- ID: `question:unknown-mermaid-edge-component-mermaid-processor-component-mermaid-st-75e904e3ff`
- Category: protocol
- Related elements: `edge:component-mermaid-processor:component-mermaid-store:mermaid`

Rationale: Protocol for Mermaid flow Processor to Payment Store is unknown.

## What rate limits protect GET /payments/{paymentId}?

- ID: `question:edge-actor-openapi-api-client-api-get-payments-paymentid-request:rate-limiting`
- Category: rate_limiting
- Related elements: `edge:actor-openapi-api-client:api-get-payments-paymentid:request`, `actor:openapi:api-client`, `api:get:payments-paymentid`

Rationale: Rate limiting is not proven for this external entry point.

## What rate limits protect POST /payments?

- ID: `question:edge-actor-openapi-api-client-api-post-payments-request:rate-limiting`
- Category: rate_limiting
- Related elements: `edge:actor-openapi-api-client:api-post-payments:request`, `actor:openapi:api-client`, `api:post:payments`

Rationale: Rate limiting is not proven for this external entry point.

## What rate limits protect payments-public-lb?

- ID: `question:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:rate-limiting`
- Category: rate_limiting
- Related elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`

Rationale: Rate limiting is not proven for this external entry point.

## What rate limits or abuse controls are enforced for Sample Payments API?

- ID: `question:unknown-readme-rate-limiting`
- Category: rate_limiting
- Related elements: `component:readme:sample-payments-api`

Rationale: Rate limiting behavior is not described in the README.

## What rate limits or abuse controls are enforced for payments-public-lb?

- ID: `question:unknown-terraform-terraform-aws-lb-public-rate-limiting`
- Category: rate_limiting
- Related elements: `terraform:aws-lb:public`

Rationale: Rate limiting for internet-exposed resource payments-public-lb is unknown.
