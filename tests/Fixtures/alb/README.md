# ALB トークンの固定データ

`AlbFixturesTest` は、このディレクトリの `*.json` をすべて検証します。

いまあるのは `AlbTokenFactory` で作った合成トークン（`synthetic-*.json`）だけです。
本物の ALB が出す形式（パディング、R‖S の署名、header の並び）と一致することを保証するには、実際の ALB から取ったトークンを追加してください。

## 本物のトークンを追加する手順

1. ALB の後ろにあるアプリで、`x-amzn-oidc-data` ヘッダーの値を 1 つ記録する（テスト用のユーザーで）。
2. header の `kid` と `signer` を確認し、`https://public-keys.auth.elb.<region>.amazonaws.com/<kid>` から PEM を取得する。
3. 次の形式で `alb-<環境>-<日付>.json` として保存する。`verify_at` は header の `exp` より前の時刻にする（テストは固定の時計で検証するので、期限が切れたトークンでもよい）。

```json
{
  "description": "staging ALB, 2026-12-01, test user",
  "token": "<x-amzn-oidc-data の値>",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "signer": "arn:aws:elasticloadbalancing:...",
  "client": "<Cognito のアプリクライアント ID>",
  "verify_at": 1795000060,
  "expect": { "sub": "...", "email": "..." }
}
```

トークンには email などの個人情報が入ります。テスト用のユーザーのものだけを使ってください。
期限切れのトークンなので、ログインには使えません。
