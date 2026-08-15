`DharmaDoll/ModelForge` の現行仕様をレビューしました。結論から言うと、**かなり筋が良いです。特に「LLMをSoTにしない」「中間表現 `system_model.json` を中心に据える」という判断が強い**です。ただし、今後の拡張をそのまま積み上げると、入力方式・脅威分析・リスク評価・Continuous化が一気に膨らみ、設計が散らかる可能性があります。

総合評価は **8.7 / 10** です。

## まず、現在の核は正しい

ModelForgeは、

```text
README / Markdown / Mermaid / OpenAPI / Terraform
                ↓
        Deterministic Extraction
                ↓
         system_model.json
                ↓
    ┌───────────┼───────────┐
    ↓           ↓           ↓
   DFD        STRIDE      ATT&CK
    ↓           ↓           ↓
 Questions    Risk       Review
```

という設計です。外部LLMはデフォルトでは呼ばれず、LLMを使う場合も `llm_candidates.json` というレビュー対象候補に隔離し、人間による明示的merge後に初めて `system_model.merged.json` に反映します。

ここは非常に良いです。

特に、

> **Unknown information is expected. ModelForge records it as questions instead of guessing.**

という設計思想が、脅威モデリング自動化では重要です。

AIによるThreat Modelingの最大の問題は「情報が無いのに、それらしいシステム構造や脅威を補完すること」なので、

```text
Unknown ≠ Infer
```

を守っている現在の方針は維持すべきです。

---

# P0：最重要なのは `system_model.json` の意味論

今のModelForgeは、中間表現をSoTにしています。

これは正解なのですが、今後、

* Kubernetes
* IAM
* SBOM
* source code
* runtime telemetry
* diagrams
* PDF/Word
* Slack
* CloudTrail

まで全部ここへ集約する構想になっています。

その場合、一番重要なのはParserではなく、

> **System Model Schema**

になります。

今後のModelForgeの価値は、実はLLMではなく、このCanonical Modelに宿る可能性が高いです。

例えば最低でも、

```text
Node
Edge
TrustBoundary
Actor
Identity
Asset
DataStore
Interface
Control
DataClassification
Deployment
Evidence
Unknown
```

くらいは別概念として扱いたいです。

特に重要なのが、

```text
Evidence
```

です。

すべてのfactについて、

```yaml
id: component.api
type: service
name: API

evidence:
  source: terraform/main.tf
  extractor: terraform
  location: 53
  confidence: deterministic
```

のように、

**「なぜModelForgeはこれを事実だと考えているのか」**

を必ず追跡できる形にする。

READMEではすでにsource file / extractor / section / lineなどのEvidence pointerを保持しているので、この方向をさらに中心に据えるべきです。

---

# P0：FactとInferenceを明確に分けたい

今後のmultimodal化では必須になります。

例えばTerraformに、

```text
aws_lb
```

があれば、

> Load Balancerが存在する

はFactです。

しかし、

> Internet-facing entry pointである

は属性次第ではInferenceです。

さらに、

> Attack surfaceが高い

はAssessmentです。

この3つを同じモデルに混ぜない方がいいです。

私は、

```text
Observation
    ↓
Fact
    ↓
Inference
    ↓
Security Assessment
```

の4層構造を推します。

例えば、

```yaml
fact:
  id: fact-001
  statement: "aws_lb.public exists"

inference:
  id: inf-001
  based_on:
    - fact-001
  statement: "Internet-facing entry point"
  confidence: 0.97

assessment:
  id: risk-001
  subject: inf-001
  threat: "Spoofing / unauthorized access"
```

です。

これによって、

**LLMが生成した推測と、Terraformから確定した事実が混ざらなくなります。**

この分離は将来的にかなり効きます。

---

# P0：STRIDEとATT&CKの関係は今のまま分離維持

現状、STRIDEとMITRE ATT&CKは別々のoutputになっています。

これは正しいです。

ここを、

```text
STRIDE → ATT&CK
```

のような単純mappingにはしない方がいいです。

それぞれ目的が違います。

```text
STRIDE
→ 設計上のSecurity property violation

ATT&CK
→ 攻撃者の行動 / technique
```

なので、

例えば、

```text
Public API
   ↓
STRIDE:
Spoofing / Elevation of Privilege

ATT&CK:
Valid Accounts
External Remote Services
```

のように、

**同一System Modelを異なるLensで読む**

構造が理想です。

今の設計はそこにかなり近いです。

---

# P1：Risk Scoringは「CVSS-aligned」をやめてもいい

`next-features-spec.md` には、

> CVSS-aligned dynamic risk rating

とあります。

ここは少し見直した方がいいです。

CVSSは本質的に、

> vulnerability severity

の尺度です。

一方ModelForgeが扱うのは、

> architecture threat

です。

まだ脆弱性が存在すると決まっているわけではありません。

例えば、

```text
Public API
+
Sensitive data
+
No auth documented
```

は重要なReview Candidateですが、

CVSS 9.1

のように出すと「脆弱性が発見された」と誤認されやすいです。

なのでModelForgeでは、

```text
Threat Priority
```

あるいは、

```text
Review Priority
```

とする方がよいです。

例えば、

```text
Exposure
× Asset Criticality
× Trust Crossing
× Control Confidence
× Attack Feasibility
```

から、

```text
Critical Review
High Review
Medium Review
Low Review
```

を出す。

READMEでも現在はHigh / Medium / Low **review priorities**として扱っているので、こちらの方が整合しています。

---

# P1：CI Gateは慎重に

現在、

```yaml
fail-on-risk: high
```

でGitHub Actionを落とせる仕様があります。

機能としては良いですが、デフォルトoffなのも正しいです。

Threat ModelingはSASTと違って、

```text
candidate
```

が多いです。

なので、

```text
Threat detected → CI fail
```

より、

```text
New unreviewed High threat
→ Review required
```

の方が自然です。

将来的には、

```text
candidate
reviewed
accepted
mitigated
false-positive
needs-context
```

というThreat lifecycleを持つ方が良いでしょう。

そうするとCI gateも、

```text
new_high_unreviewed > 0
```

のような条件にできます。

これはContinuous Threat Modelingにかなり重要です。

---

# P1：Continuous Threat Modelingは「差分」が核心

ROADMAPではRuntime Telemetryまで取り込み、

> Continuous Threat Modeling

を目指しています。

その場合、本当に重要なのは再生成ではなく、

```text
Model Diff
```

です。

例えばPRで、

```text
Before

Web → API → DB
```

だったものが、

```text
After

Web → API → DB
       ↓
   External SaaS
```

になった場合、

全部のThreat Modelを再レビューさせるのではなく、

```text
New component:
External SaaS

New trust boundary crossing:
API → SaaS

New data flow:
PII → SaaS

New threats:
T-31
T-32
```

だけ見せる。

これが本当のShift-left Threat Modelingです。

したがって将来的に、

```text
system_model.base.json
system_model.current.json
        ↓
     Model Diff
        ↓
Threat Delta
```

という機能をCoreに入れたいです。

個人的にはこれは、JiraやSlack連携より優先順位が高いです。

---

# P1：Multimodal Inputを一気に作らない

ROADMAPは非常に野心的です。

PDF、Word、PowerPoint、画像、Slack、source code、eBPF、CloudTrailまであります。

Visionとしては良いです。

ただ、これを順番にAdapterとして実装していくと、

**巨大なParser Collection**

になってしまいます。

なのでInput Pipelineを、

```text
Raw Artifact
    ↓
Extractor
    ↓
Candidate Observation
    ↓
Normalization
    ↓
Evidence Validation
    ↓
System Model
```

に統一した方がいいです。

つまり各Extractorは、

```text
system_model.json
```

を直接作らない。

必ず、

```text
CandidateObservation[]
```

を出す。

例えば、

```json
{
  "type": "service_candidate",
  "name": "Payment API",
  "source": "architecture.png",
  "extractor": "vision",
  "confidence": 0.82
}
```

です。

そこからNormalizerがCanonical Modelへ入れる。

これで、

```text
Terraform parser
OpenAPI parser
Vision model
LLM
Source code parser
```

を同じTrust Modelで扱えます。

---

# P1：LLMの役割は今の仕様よりさらに限定してもよい

現状LLMは、

* README extraction
* question refinement

に限定されています。

これは現在として非常に良いです。

`next-features-spec.md`では将来的に、

> static rulesの結果をLLMへ送り、高度なthreat scenarioをrefine

としています。

ここでも、

```text
LLM → Threat
```

ではなく、

```text
LLM → ThreatCandidate
```

にした方がいいです。

例えば、

```text
Deterministic rule:
Public API crosses trust boundary

        ↓

LLM:
"This may enable account takeover if authentication
is token-based and audience validation is absent."

        ↓

ThreatCandidate
confidence: medium
missing_fact:
- authentication mechanism
- token validation

        ↓

questions.md
```

とする。

つまりLLMの仕事は、

**脅威を断定することではなく、仮説と不足情報を生成すること**

です。

---

# P1：Anonymization Guardは少し再考

`next-features-spec.md`では、

> ARNやIP、DB endpoint等をmaskしてexternal LLMへ送る

構想があります。

防御としては良いですが、

「匿名化したから安全」

とはしない方がいいです。

アーキテクチャ自体が機密情報だからです。

例えば、

```text
Service_A → DB_1 → SaaS_2
```

でも構造自体に価値があります。

したがってPolicyは、

```text
External LLM transmission
=
explicit opt-in
+
data classification check
+
minimized context
+
optional redaction
```

とする。

匿名化は補助controlです。

---

# P2：NetworkXは実装詳細に留める

`next-features-spec.md`にはNetworkX利用案があります。

利用自体は合理的ですが、仕様として、

> NetworkX must be used

に近い形にはしない方がいいです。

重要なのは、

```text
Graph abstraction
```

です。

つまり、

```python
GraphAnalyzer
```

interfaceを持って、

* reachability
* boundary crossing
* entrypoint paths
* shortest attack path
* sensitive-data path

などを計算する。

NetworkXはその実装の1つにしておく。

---

# P2：Gold Standard Regressionはかなり重要

これは非常に良いです。

`next-features-spec.md`では、

```text
TPR
FPR
FNR
```

をfixtureで測る構想になっています。

これは早めた方がいいです。

AIを後から入れるのであればなおさら、

```text
deterministic v1

vs

deterministic + LLM
```

で、

```text
Recall ↑?
Precision ↓?
Unknown ↓?
Review effort ↓?
```

を測定できます。

できればさらに、

```text
Threat Recall
False Candidate Rate
Question Usefulness
Model Extraction Accuracy
```

を分けると良いです。

Threat DetectionとModel Extractionは別問題だからです。

---

# 私ならModelForgeをこう再定義します

現状は、

> Automated threat modeling tool

ですが、もっと正確には、

> **Evidence-backed System Modeling and Threat Analysis Engine**

だと思います。

中核は、

```text
                   Raw Inputs
                       │
       ┌───────────────┼───────────────┐
       ↓               ↓               ↓
 Terraform          OpenAPI          Documents
 Mermaid            Source            Runtime
       │               │               │
       └───────────────┼───────────────┘
                       ↓
             Candidate Observations
                       ↓
                 Validation
                       ↓
                System Model
                       ↓
          ┌────────────┼────────────┐
          ↓            ↓            ↓
        STRIDE        ATT&CK       Risk
          ↓            ↓            ↓
          └────────────┼────────────┘
                       ↓
                 Threat Candidates
                       ↓
               Missing Context
                       ↓
              Human Review / CI
```

LLMは横から、

```text
Unstructured Input
        ↓
Candidate Observation

Threat Candidate
        ↓
Context refinement
```

だけ支援する。

これならかなり堅牢です。

---

## 優先順位

| 優先     | 改善                                                              |
| ------ | --------------------------------------------------------------- |
| **P0** | `system_model.json` のCanonical Schemaを最重要仕様として固定                |
| **P0** | Fact / Inference / Assessmentを分離                                |
| **P0** | 全model elementにEvidence / provenanceを持たせる                       |
| **P1** | Input Adapter → Candidate Observation → Normalizeという共通pipeline化 |
| **P1** | Continuous化の中心をModel Diff / Threat Deltaにする                     |
| **P1** | Threat lifecycle（candidate/reviewed/accepted/mitigated）を導入      |
| **P1** | RiskをCVSSではなくReview Priorityとして扱う                               |
| **P1** | LLM outputは常にCandidate扱い                                        |
| **P2** | Gold Standard evaluationを前倒し                                    |
| **P2** | Anonymizationは外部LLM送信の補助controlとして扱う                            |

今のModelForgeで特に面白いのは、**Threat Modelingそのものより「バラバラな設計情報から、Evidence付きのSystem Modelを自動生成する」という部分**です。ここを本当のコアにすると、その上にThreat Modeling、Security Review、Architecture Review、Continuous Threat Modeling、さらにはAI Agent向けSecurity Contextまで載せられます。
