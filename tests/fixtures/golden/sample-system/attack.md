# MITRE ATT&CK Technique Candidates

Generated deterministically from `system_model.json`. These are candidate TTP mappings, not evidence that an attack occurred.

Total ATT&CK findings: 2

| ID | Technique | Tactics | Title | Confidence |
| --- | --- | --- | --- | --- |
| `attack:t1190:attack-public-entrypoint:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public` | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Initial Access | Public-facing application technique candidate for payments-public-lb | high |
| `attack:t1499:attack-entrypoint-dos:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public` | [T1499 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/) | Impact | Endpoint denial-of-service technique candidate for payments-public-lb | medium |

## Public-facing application technique candidate for payments-public-lb

- ID: `attack:t1190:attack-public-entrypoint:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public`
- Rule: `attack-public-entrypoint`
- Technique: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- Tactics: Initial Access
- Matrix: Enterprise ATT&CK
- Confidence: high
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Scenario: payments-public-lb is reachable from Internet. The model does not prove patching, WAF coverage, or exploit prevention controls.

Detection: Review web/API exploitation telemetry, WAF events, application errors, and ingress logs.

Mitigation: Patch exposed software, minimize exposed endpoints, validate inputs, and deploy WAF controls.

## Endpoint denial-of-service technique candidate for payments-public-lb

- ID: `attack:t1499:attack-entrypoint-dos:edge-actor-terraform-internet-terraform-aws-lb-public-public-access:actor-terraform-internet:terraform-aws-lb-public`
- Rule: `attack-entrypoint-dos`
- Technique: [T1499 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- Tactics: Impact
- Matrix: Enterprise ATT&CK
- Confidence: medium
- Status: candidate
- Affected elements: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Derived from: `edge:actor-terraform-internet:terraform-aws-lb-public:public-access`, `actor:terraform:internet`, `terraform:aws-lb:public`
- Evidence: `main.tf:28` (terraform/terraform, resource "aws_lb" "public"); `derived` (terraform/terraform, internet exposure)

Scenario: payments-public-lb receives traffic from Internet, and rate limiting or capacity controls are not proven in the model.

Detection: Monitor request rate, latency, error-rate spikes, queue depth, and saturation metrics.

Mitigation: Apply rate limits, request budgets, autoscaling, backpressure, and upstream filtering.
