# ModelForge クイックスタート：決済 API の設計レビューを始める

ModelForge は README、OpenAPI、Terraform、Mermaid の設計図から、レビュー用の脅威モデルをローカルで生成します。最初に得られるのは「脆弱性の判定」ではなく、**根拠のある構成図、検討すべき脅威候補、設計者に聞くべき質問**です。セキュリティ担当者が白紙から図を描く代わりに、チームで確認できる下書きから始められます。

このガイドでは同梱の架空の決済サービスを使います。AWS へのデプロイも API キーも不要です。通常の `analyze` は外部 LLM にファイルを送信しません。

## まず 1 回動かす

Python 3.12 以上と `uv` を用意し、リポジトリのルートで実行します。初回の `uv run` では Python 依存パッケージの取得が必要な場合があります。

```bash
git clone https://github.com/DharmaDoll/ModelForge.git
cd ModelForge
uv run tm-ai analyze ./examples/sample-system --out ./out/sample-system
```

すでにリポジトリを開いている場合は、`git clone` と `cd` は不要です。コマンドが `Wrote .../system_model.json` などを表示したら成功です。まず次の 2 ファイルを開いてください。

```text
out/sample-system/review.md       全体像とレビュー優先順位
out/sample-system/questions.md    まだ確認が必要な設計事項
```

`review.md` はノード・データフロー・STRIDE 候補・質問の件数を短くまとめ、最初に確認したい質問へのリンクを最大5件示します。`questions.md` には、たとえば「`GET /payments/{paymentId}` を保護する認可チェックは何か」「`POST /payments` にどんなレート制限があるか」といった質問が並びます。現在のサンプルでは45件の元質問を38のレビュータスクに整理しています。これは表示上の整理で、個々の質問 ID・根拠・Unknown を削除したものではありません。これらは対策が*存在しない*という断定ではなく、入力資料からは確認できなかったという意味です。

モデルの形式も確認するなら、次を実行します。`Valid system model: schema 0.1.` と表示されれば、参照関係を含む現在のモデル検証に通っています。

```bash
uv run tm-ai model validate ./out/sample-system/system_model.json
```

## サンプルの読み方：公開入口からレビューを始める

題材の [`sample-system`](../examples/sample-system/README.md) には、決済 API の説明、[OpenAPI](../examples/sample-system/openapi.yaml)、[Terraform](../examples/sample-system/main.tf)、[Mermaid 設計図](../examples/sample-system/docs/architecture.md) が入っています。次の順に読むと、生成物がレビューの会話につながります。

1. `out/sample-system/review.md` の「Suggested Starting Questions」で、最初に見るべき入口と未回答の質問を把握します。`Open` から同じ対象・検討事項の質問と根拠に移動できます。ここでの順序は閲覧の案内で、新しいリスクスコアではありません。
2. `out/sample-system/risk.md` で `payments-public-lb` の優先順位と理由を読みます。Terraform の `internal = false` が公開入口の根拠です。ここでの High / Medium / Low は**レビュー優先順位**であり、CVSS や確定した脆弱性の深刻度ではありません。
3. `out/sample-system/dfd.mmd` で、生成されたデータフロー図を Mermaid 対応ビューアで確認します。図にない接続を想像で補わず、`out/sample-system/system_model.json` のノード・エッジと根拠を確認します。
4. `out/sample-system/questions.md` の「Review Tasks」から、API の認可、データ分類、レート制限など、担当者に確認する問いを選びます。似た問いをまとめても、元の ID と Evidence は各タスクの詳細に残ります。回答後に入力資料を更新して再実行できます。

`attack.md` や `threats.md` の `Confidence` は、候補がルールと入力の根拠にどの程度合致するかを示します。一方、`risk.md` の `Rating` / `Score` は、モデル上の事実から決めた**レビュー優先度**です。これは別々の尺度です。たとえばこのサンプルでは、公開ロードバランサーに対する ATT&CK 候補の Confidence は `high` ですが、同じ入口のレビュー優先度は `Low`（スコア3）です。いずれも CVSS、脆弱性の確定した深刻度、悪用可能性の証明ではありません。

ここで重要なのは、サンプルの公開ロードバランサーと OpenAPI の各操作が**同じ経路でつながっているとは証明されていない**ことです。ModelForge は別々の資料に現れた要素を表示しますが、裏付けのない接続は作りません。図や結果に不足が見つかれば、それ自体が設計レビューの成果です。

`review.md` の「Unresolved Identity Candidates」には、README と OpenAPI の両方に出てくる `Sample Payments API` が**別々のノード**として表示されます。同名であることは同一システム要素の証拠にはなりません。資料名と ID を手掛かりに担当者へ確認してください。この候補表示によってモデルや DFD のノード・接続が自動で統合されることはありません。

機密設計の `dfd.mmd` を見るときは、社内で許可されたローカルの Mermaid ビューアを使ってください。公開のオンラインビューアに貼り付ける必要はありません。

## シナリオ 1：新しい API のレビューを依頼されたら

開発チームから README と OpenAPI だけ渡されたとします。まず、資料が置かれたディレクトリを指定します。

```bash
uv run tm-ai analyze /path/to/service --out ./out/service-review
```

ルートの `README.md` と `openapi.yaml` / `openapi.yml` / `openapi.json`（または `swagger` 名）は自動検出されます。足りない Terraform や設計図を作ってまで実行する必要はありません。出力の `questions.md` は、資料に書かれていない認証・認可やデータ保護を確認するための質問リストになります。レビュー会議では `review.md` を入口にし、回答の根拠を README や API 定義へ反映してください。

ファイル名が異なる場合は、`--readme`、`--openapi`、`--terraform`、`--doc` で個別指定できます。`--terraform` と `--doc` は複数回指定できます。

```bash
uv run tm-ai analyze /path/to/service \
  --readme /path/to/service/README.md \
  --openapi /path/to/service/api/payments.yaml \
  --out ./out/service-review
```

## シナリオ 2：設計図とインフラ定義の境界を確認したい

同梱サンプルでは Mermaid に `Application Boundary`、Terraform にプライベートサブネットが明示されています。`dfd.mmd` にはその境界が現れます。一方、`questions.md` には API 操作や公開入口がどの信頼境界に属するかを問う項目も出ます。

設計レビューでは「境界が図にある」だけで終えず、どの入口・データフローが境界を越えるのかを開発者と確認してください。必要な接続や制御が資料に欠けていれば、設計図や OpenAPI / Terraform を直して再実行します。`dfd.mmd` は生成物なので直接編集せず、入力資料を修正するのが基本です。

## シナリオ 3：CI 導入前にローカルで判定を試す

レビュー優先順位の閾値を使うと、CI で後から使える終了コードを手元で試せます。

```bash
uv run tm-ai check ./out/sample-system/system_model.json --fail-on high
```

現在のサンプルでは `high` に該当するリスク候補がないため、このチェックは成功します。`--fail-on low` なら候補が閾値に達して失敗します。**この差は安全性の合格・不合格ではありません。** 候補をレビューしたうえで、チームに合う閾値を決めてください。GitHub Actions への組み込み例は [README の GitHub Action 節](../README.md#github-action) にあります。

コールドスタートの手順は、既存の `.venv` がない別コピーで Python 3.13.5、uv 0.11.21 を使って確認しました。初回の依存取得にはネットワーク接続が必要でした。2回目の `analyze` は8ファイルすべてがバイト単位で一致し、`model validate` は成功、`check --fail-on high` は終了コード0、`--fail-on low` は終了コード1でした。自動テストも同じ成果物・検証・終了コードを確認しますが、依存パッケージの新規取得そのものはネットワーク環境に左右されます。

## 生成ファイルと次の一歩

| ファイル | 使いどころ |
| --- | --- |
| `system_model.json` | 抽出された要素・関係と根拠を確認する。すべてのレポートの元データ。 |
| `dfd.mmd` | システムのデータフローと明示された信頼境界を見る。 |
| `review.md` / `risk.md` | 全体像とレビュー順を決める。 |
| `threats.md` / `attack.md` | STRIDE と MITRE ATT&CK の候補を検討する。 |
| `questions.md` | 不明点を担当者に確認する。 |
| `ingestion.json` | 入力種別ごとの抽出候補数、Mermaid・OpenAPI の解析／スキップ件数、Terraform の認識リソース数と ID 衝突数を見る。構成の網羅率ではない。 |
| `threat_hypotheses.json` | 任意のLLMシャドーモードで生成する、未採用の脅威仮説。通常の `analyze` では生成しない。 |

自分のリポジトリで試すときは、生成先を分析対象の**外側**に置くと、次回の自動検出で生成された Markdown を再入力することを避けられます。機密性の高い設計を扱う場合も、保存先のアクセス権や共有範囲を確認してください。通常モードはローカル処理ですが、生成レポートには構成情報が含まれます。

`analyze` の出力では、分析対象ディレクトリ内の根拠ファイルはそのディレクトリからの相対パスになります。異なるチェックアウト場所でも同じモデルを比較しやすく、作業者のホームパスも出ません。ただし `--readme` などで対象外のファイルを明示指定した場合、その出所を追えるよう絶対パスを残します。共有前には対象外ファイルのパスと機密情報を確認してください。既存モデルを `render` する操作は根拠パスを書き換えません。

`No supported input files were found` と表示されたら、対象ディレクトリに対応する README、OpenAPI、Terraform、Mermaid を含む Markdown のいずれかがあるか確認してください。標準のファイル名や場所と違うときは、上の明示指定オプションを使います。

## 任意：LLM で質問を読みやすくする

質問の文面だけを整えたい場合は、外部送信を許可できる資料に限り、`OPENAI_API_KEY` を安全な方法で環境変数へ設定してから明示的に実行します。

```bash
uv run tm-ai analyze ./examples/sample-system \
  --out ./out/sample-system-llm \
  --llm refine-questions
```

送信するのは質問ID・カテゴリ・元の質問文です。元ファイル全体や `system_model.json`、証拠のファイルパスは送りません。ただし**質問文自体にシステム名やAPI名が含まれる**ため、機密情報の外部送信を許可できるか先に確認してください。生成される `questions_refined.md` は元の質問と提案文を並べたレビュー用ファイルで、元の `questions.md` を置き換えません。IDが欠けるなど応答が検証に失敗した場合、コマンドは失敗し、新しいリファイン結果は書きません。出力先に以前の `questions_refined.md` がある場合は古い可能性があるため、成功表示を確認してから利用してください。

## 任意：LLMと脅威仮説を壁打ちする

ルールが挙げた候補とは別に、「この設計なら他に何を確かめるべきか」を探したいときは、脅威仮説のシャドーモードを使えます。まずサンプルの `POST /payments` を対象に、**外部へ送る予定の情報をローカルで確認**します。この段階ではAPIキーも外部通信も不要です。

```bash
uv run tm-ai hypotheses preview-context \
  ./out/sample-system/system_model.json \
  --element api:post:payments \
  --out ./out/sample-system/challenger_context.preview.json
```

プレビューファイルを開き、ノード名・API名・認証方式などを外部LLMへ送ってよいか判断してください。送信対象は選択した要素の周辺1ホップのグラフ情報とEvidenceの参照番号です。元ファイル、根拠のパスや本文、任意のメタデータは送りません。ただしIDや名前だけでも機密構成が分かる場合があります。許可できない場合はここで止め、通常のローカルレビューを続けてください。

送信を承認できる場合のみ、`OPENAI_API_KEY` を安全な方法で設定し、データ分類と明示承認を付けて実行します。次は内部情報の送信が組織の方針上承認済みの場合の例です。公開情報なら `--classification public` を選びます。

```bash
uv run tm-ai hypotheses propose \
  ./out/sample-system/system_model.json \
  --element api:post:payments \
  --classification internal-approved \
  --allow-external-llm \
  --out ./out/sample-system/threat_hypotheses.json

uv run tm-ai hypotheses validate \
  ./out/sample-system/threat_hypotheses.json \
  --model ./out/sample-system/system_model.json
```

`threat_hypotheses.json` の各項目では、`established_prerequisites` とEvidence参照を元モデルで確かめ、`assumptions` と `missing_facts` を担当者に聞き、`verification_steps` をレビュー作業に移します。たとえば「もしリプレイ防止がなければ」という仮説は、リプレイ防止が*ない*という発見ではありません。妥当な仮説がなければ0件も正常です。モデルを再生成した後は、古い仮説ファイルを新モデルに流用せず、再検証・再生成してください。

候補IDの一覧と、まだレビューしていない候補を確認するには次を実行します。

```bash
uv run tm-ai hypotheses review-status \
  ./out/sample-system/threat_hypotheses.json \
  --model ./out/sample-system/system_model.json
```

調査する価値があるか、情報不足か、棄却するかの判断を残せます。次の `--id` は一覧からコピーした実際のIDに置き換えてください。

```bash
uv run tm-ai hypotheses decide \
  ./out/sample-system/threat_hypotheses.json \
  --model ./out/sample-system/system_model.json \
  --id hypothesis:0123456789abcdef \
  --disposition needs_context \
  --reviewer your-name \
  --rationale "リプレイ防止の実装根拠を確認する" \
  --state ./out/sample-system/hypothesis_review.json
```

判断は `investigate`（調査する）、`needs_context`（追加情報待ち）、`rejected`（棄却）の3種類です。`hypothesis_review.json` に担当者・理由・日時と変更履歴が保存されます。`review-status` に `--state` を加えると最新の判断を表示できます。担当者名は自己申告であり、認証ではありません。仮説やモデルが変われば以前の判断は自動で引き継がれません。

仮説の生成やレビュー判断は、`system_model.json`、`threats.md`、`risk.md`、CI判定には反映しません。`investigate` も確定した脆弱性ではありません。判断ファイルにも機密情報が含まれ得るため共有範囲を確認してください。ルールのみの場合との品質比較と、正式な発見事項への昇格手順はまだ開発中です。まず設計者との会話を深める材料にしてください。

最初のレビューが終わったら、`system_model.json` の事実と根拠を確認し、未回答の質問を設計資料に反映して再実行してください。資料が良くなるほど、次の脅威モデルの下書きも良くなります。
