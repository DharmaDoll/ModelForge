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

### Highest Priorities

| Rating | Score | Finding |
| --- | ---: | --- |
| Low | 3 | Review priority for payments-public-lb entry point |
| Low | 2 | Review priority for GET /payments/{paymentId} entry point |
| Low | 2 | Review priority for POST /payments entry point |

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
