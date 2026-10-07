<!-- modelforge-review -->
# ModelForge Review Summary

Generated deterministically from `system_model.json`. All findings are review candidates, not confirmed vulnerabilities.

## Coverage

| Nodes | Data flows | Unknowns | STRIDE | ATT&CK | Questions |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 21 | 8 | 21 | 24 | 2 | 45 |

## Risk Priorities

| High | Medium | Low | Total |
| ---: | ---: | ---: | ---: |
| 0 | 0 | 3 | 3 |

STRIDE/ATT&CK confidence (high/medium/low) describes how strongly a candidate matches its deterministic rule and evidence. Risk rating (High/Medium/Low) and score order review attention from modeled facts. These are separate scales: neither is CVSS, confirmed vulnerability severity, or exploitability proof.

### Highest Priorities

| Rating | Score | Finding |
| --- | ---: | --- |
| Low | 3 | Review priority for payments-public-lb entry point |
| Low | 2 | Review priority for GET /payments/{paymentId} entry point |
| Low | 2 | Review priority for POST /payments entry point |

## Suggested Starting Questions

45 underlying questions form 38 review tasks. These are navigation suggestions, not new risk scores; no question or evidence was discarded.

| Subject | Review focus | Questions | Details |
| --- | --- | ---: | --- |
| Internet → payments-public-lb | How is payments-public-lb authenticated when called by Internet? | 1 | [Open](questions.md#question-group-076fc4cecb) |
| API Client → GET /payments/{paymentId} | What authorization checks protect GET /payments/{paymentId}? | 2 | [Open](questions.md#question-group-943b7dc6ec) |
| API Client → POST /payments | What authorization checks protect POST /payments? | 2 | [Open](questions.md#question-group-40f611654f) |
| Internet → payments-public-lb | What authorization checks protect payments-public-lb? | 1 | [Open](questions.md#question-group-87934b869a) |
| API Client → GET /payments/{paymentId} | What rate limits protect GET /payments/{paymentId}? | 1 | [Open](questions.md#question-group-a963c98f8e) |

## Unresolved Identity Candidates

1 same-name group(s) span distinct source files. Names alone do not prove identity: no nodes, flows, or reviewer decisions were merged. Source hints below omit local directories; full Evidence remains in `system_model.json`.

- Sample Payments API — possible pair (2 separate nodes)
  - `component:openapi:sample-payments-api` (component; `openapi:openapi.yaml`)
  - `component:readme:sample-payments-api` (component; `readme:README.md`)

## Open Question Categories

| Category | Count |
| --- | ---: |
| authentication | 7 |
| authorization | 10 |
| data_classification | 4 |
| encryption | 7 |
| logging | 1 |
| logging_monitoring | 4 |
| monitoring | 1 |
| protocol | 2 |
| rate_limiting | 6 |
| trust_boundary | 3 |

Review `system_model.json` first, then `risk.md`, `threats.md`, `attack.md`, and `questions.md` for details.
