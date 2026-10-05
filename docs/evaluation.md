# Labeled-probe evaluation

ModelForge can compare deterministic model and analysis outputs against authored
positive and negative probes:

```bash
tm-ai evaluate tests/fixtures/evaluation/manifest.json
tm-ai evaluate tests/fixtures/evaluation/manifest.json --json
```

The current fixture set contains six small cases and 61 probes across model
extraction, STRIDE, ATT&CK, questions, and review priority. The labels have
`review_status: seed`: they are regression examples, **not** an expert-reviewed
gold standard. The report states how many probes have expert-reviewed labels.
No external LLM is called, and evaluation creates only temporary analysis
artifacts.

## What is measured

Each probe names one lens and one selector, gives an expected presence/absence,
and records its rationale. Only those explicitly labeled probes enter the
confusion matrix. Unlabeled outputs are neither false positives nor true
negatives. Model selectors may target a specific node or edge, or one of the
documented summary properties in the evaluator.

The cases cover explicit private/public load balancers, an unresolved LB exposure
setting, a declared API key, an operation-level unauthenticated override, and
omitted API security. A model probe such as
`auth:edge:actor-openapi-api-client:api-get-status:request:none` targets one
specific edge's authentication state; `known`, `none`, and `unknown` are kept
distinct. This avoids a case-wide `known_authentication` result hiding an
unauthenticated operation in the same API.
Model, risk, STRIDE, and ATT&CK selectors are validated against their supported
vocabularies; a typo in a negative probe fails evaluation instead of silently
counting as a true negative. Question categories remain extensible and are not
yet constrained to a fixed vocabulary.

For labeled probes, `TP`, `FP`, `TN`, and `FN` have their usual binary meanings.
The reported ratios are:

| Metric | Formula | Meaning |
| --- | --- | --- |
| Precision | TP / (TP + FP) | Fraction of predicted-positive probes that are labeled positive |
| Recall / TPR | TP / (TP + FN) | Fraction of labeled positives detected |
| False-candidate rate | FP / (TP + FP) | Fraction of predicted-positive probes labeled negative |
| FPR | FP / (FP + TN) | Fraction of labeled negatives predicted positive |
| FNR | FN / (TP + FN) | Fraction of labeled positives missed |

A ratio with a zero denominator is `null`, not zero. Metrics are calculated
separately for each lens and as a micro aggregate. They describe this labeled
probe set only; they are not estimates of production prevalence or vulnerability
severity. Question usefulness, full model precision/recall, and comparisons
against optional LLM runs require additional reviewed labels and are not yet
claimed.

## Growing the fixture set

Add a small project directory under `tests/fixtures/evaluation/`, then add a
case to `manifest.json`. Give every probe a source-grounded rationale and both
positive and negative examples where possible. Use `expert_reviewed` only after
a named security reviewer has reviewed the labels; the `reviewer` field records
that attribution but is not an authentication mechanism. Do not promote seed
metrics into CI acceptance thresholds. New selectors and expert-reviewed
coverage should be added before using the metrics to compare rule, schema, or
prompt changes.
