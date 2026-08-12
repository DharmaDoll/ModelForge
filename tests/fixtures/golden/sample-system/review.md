<!-- modelforge-review -->
# ModelForge Review Summary

Generated deterministically from `system_model.json`. All findings are review candidates, not confirmed vulnerabilities.

## Coverage

| Nodes | Data flows | Unknowns | STRIDE | ATT&CK | Questions |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 21 | 11 | 21 | 26 | 12 | 45 |

## Risk Priorities

| High | Medium | Low | Total |
| ---: | ---: | ---: | ---: |
| 4 | 1 | 0 | 5 |

### Highest Priorities

| Rating | Score | Finding |
| --- | ---: | --- |
| High | 8 | Review priority for GET /payments/{paymentId} entry point |
| High | 8 | Review priority for POST /payments entry point |
| High | 8 | Review priority for payments-public-lb entry point |
| High | 7 | Review priority for Payments Gateway entry point |
| Medium | 5 | Review priority for storage path to payments-db |

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
