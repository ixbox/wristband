# Changelog

## 0.3.0（2026-11-28）

- `NativeHttpClient` の第 2 引数で、信頼する CA 証明書のファイルを指定できるようにした（社内 CA、ローカルのエミュレータなど）。
- テスト：AWS Emulator の Cognito が発行したトークンを、discovery と JWKS の HTTPS 取得を含めて検証する結合テストと、その CI のジョブを追加した。

## 0.2.1（2026-11-27）

- 依存の下限を、実際に必要な版まで下げた：`symfony/polyfill-ctype` を `^1.8`、`symfony/polyfill-php80` を `^1.16`（`str_starts_with` が入った版）。

## 0.2.0（2026-11-27）

- `BearerConfig::withRequiredScopes()` と `withRequiredClaims()`：必須の scope と claim を確かめる（ALB の JWT 検証の `AdditionalClaims` に相当）。
- `Identity::scopes()`、`hasScope()`、`clientId()`。
- ドキュメント：ALB の JWT 検証（`jwt-validation`）との対応。

## 0.1.0（2026-11-27）

- `AlbTokenVerifier`：ALB の `x-amzn-oidc-data`（ES256）を検証する。
- `BearerTokenVerifier`：OIDC の JWT（RS256、ES256）を JWKS で検証する。
- source：`AlbOidcDataSource`、`BearerJwtSource`、`TrustedHeadersSource`、`ChainSource`。
- 公開鍵と JWKS の取得とキャッシュ：`HttpKeyProvider`、`CachedKeyProvider`、`HttpJwksProvider`、`Psr16Cache`。
- ログアウトの補助：`AlbLogout`、`Oauth2ProxyLogout`。
- テスト用の道具：`AlbTokenFactory`、`JwtTokenFactory`、`FrozenClock`。
