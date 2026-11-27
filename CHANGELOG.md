# Changelog

## 0.1.0（未リリース）

- `AlbTokenVerifier`：ALB の `x-amzn-oidc-data`（ES256）を検証する。
- `BearerTokenVerifier`：OIDC の JWT（RS256、ES256）を JWKS で検証する。
- source：`AlbOidcDataSource`、`BearerJwtSource`、`TrustedHeadersSource`、`ChainSource`。
- 公開鍵と JWKS の取得とキャッシュ：`HttpKeyProvider`、`CachedKeyProvider`、`HttpJwksProvider`、`Psr16Cache`。
- ログアウトの補助：`AlbLogout`、`Oauth2ProxyLogout`。
- テスト用の道具：`AlbTokenFactory`、`JwtTokenFactory`、`FrozenClock`。
