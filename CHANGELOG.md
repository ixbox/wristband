# Changelog

## 0.2.0（未リリース）

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
