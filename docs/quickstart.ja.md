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

## サンプルの読み方：公開入口からレビューを始める

題材の [`sample-system`](../examples/sample-system/README.md) には、決済 API の説明、[OpenAPI](../examples/sample-system/openapi.yaml)、[Terraform](../examples/sample-system/main.tf)、[Mermaid 設計図](../examples/sample-system/docs/architecture.md) が入っています。次の順に読むと、生成物がレビューの会話につながります。

1. `out/sample-system/review.md` の「Suggested Starting Questions」で、最初に見るべき入口と未回答の質問を把握します。`Open` から同じ対象・検討事項の質問と根拠に移動できます。ここでの順序は閲覧の案内で、新しいリスクスコアではありません。
2. `out/sample-system/risk.md` で `payments-public-lb` の優先順位と理由を読みます。Terraform の `internal = false` が公開入口の根拠です。ここでの High / Medium / Low は**レビュー優先順位**であり、CVSS や確定した脆弱性の深刻度ではありません。
3. `out/sample-system/dfd.mmd` で、生成されたデータフロー図を Mermaid 対応ビューアで確認します。図にない接続を想像で補わず、`out/sample-system/system_model.json` のノード・エッジと根拠を確認します。
4. `out/sample-system/questions.md` の「Review Tasks」から、API の認可、データ分類、レート制限など、担当者に確認する問いを選びます。似た問いをまとめても、元の ID と Evidence は各タスクの詳細に残ります。回答後に入力資料を更新して再実行できます。

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

## 生成ファイルと次の一歩

| ファイル | 使いどころ |
| --- | --- |
| `system_model.json` | 抽出された要素・関係と根拠を確認する。すべてのレポートの元データ。 |
| `dfd.mmd` | システムのデータフローと明示された信頼境界を見る。 |
| `review.md` / `risk.md` | 全体像とレビュー順を決める。 |
| `threats.md` / `attack.md` | STRIDE と MITRE ATT&CK の候補を検討する。 |
| `questions.md` | 不明点を担当者に確認する。 |

自分のリポジトリで試すときは、生成先を分析対象の**外側**に置くと、次回の自動検出で生成された Markdown を再入力することを避けられます。機密性の高い設計を扱う場合も、保存先のアクセス権や共有範囲を確認してください。通常モードはローカル処理ですが、生成レポートには構成情報が含まれます。

`No supported input files were found` と表示されたら、対象ディレクトリに対応する README、OpenAPI、Terraform、Mermaid を含む Markdown のいずれかがあるか確認してください。標準のファイル名や場所と違うときは、上の明示指定オプションを使います。

## 任意：LLM で質問を読みやすくする

質問の文面だけを整えたい場合は、外部送信を許可できる資料に限り、`OPENAI_API_KEY` を安全な方法で環境変数へ設定してから明示的に実行します。

```bash
uv run tm-ai analyze ./examples/sample-system \
  --out ./out/sample-system-llm \
  --llm refine-questions
```

送信するのは質問ID・カテゴリ・元の質問文です。元ファイル全体や `system_model.json`、証拠のファイルパスは送りません。ただし**質問文自体にシステム名やAPI名が含まれる**ため、機密情報の外部送信を許可できるか先に確認してください。生成される `questions_refined.md` は元の質問と提案文を並べたレビュー用ファイルで、元の `questions.md` を置き換えません。IDが欠けるなど応答が検証に失敗した場合、コマンドは失敗し、新しいリファイン結果は書きません。出力先に以前の `questions_refined.md` がある場合は古い可能性があるため、成功表示を確認してから利用してください。

最初のレビューが終わったら、`system_model.json` の事実と根拠を確認し、未回答の質問を設計資料に反映して再実行してください。資料が良くなるほど、次の脅威モデルの下書きも良くなります。
