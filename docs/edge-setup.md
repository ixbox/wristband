# 前段（ALB、oauth2-proxy）の設定と注意点

このライブラリは、前段が認証を済ませたリクエストだけがアプリに届く構成を前提にしている。
検証の処理が正しくても、前段の設定に穴があると、なりすましを許す。
ここでは、前段ごとに確かめるべき設定を挙げる。

## ALB と Cognito

### リスナーのルール

ルールは上から順に評価される。
認証から外すパスを先に置き、最後に `authenticate-cognito` と `forward` の組を置く。

| 順 | 条件 | アクション |
|---|---|---|
| 1 | `/healthz`、`/logged-out`、そのほか認証の外に置くパス | `forward` |
| 2 | ヘッダー `X-Requested-With: XMLHttpRequest` | `authenticate-cognito`（`OnUnauthenticatedRequest=deny`）、`forward` |
| 3 | 既定 | `authenticate-cognito`（`OnUnauthenticatedRequest=authenticate`）、`forward` |

2 番目のルールがないと、セッションが切れた XHR が Cognito のログイン画面への 302 を受け取り、画面側で扱えない。
`deny` にすると 401 が返るので、画面側で再読み込みできる。
guard は未認証のリクエストに対して null を返すだけで、401 の応答は作らない。

### アプリ側に渡す値

| 値 | 取得元 |
|---|---|
| signer の ARN | ALB の ARN（`arn:aws:elasticloadbalancing:<region>:<account>:loadbalancer/app/<name>/<id>`） |
| client | Cognito のアプリクライアント ID |
| iss | `https://cognito-idp.<region>.amazonaws.com/<user pool id>` |

### 注意点

- ALB の認証の外に置いたパス（ルール 1）にも、クライアントは `x-amzn-oidc-data` を付けて送れる。
  ALB は認証したリクエストでは同名のヘッダーを付け直すが、認証の外のパスでは何もしない可能性がある。
  署名と signer を検証するので、偽のヘッダーで認証されることはない。
  ただし、偽のヘッダーを検証のエラーとしてログに残すので、認証の外のパスで guard を動かさないか、ログを調べるときにこの経路を考慮する。
- セキュリティグループで、アプリには ALB からしか届かないようにする。
  検証があるので必須ではないが、前段を迂回した経路は少ないほうがよい。
- ALB の認証 cookie は最大 16KB（4 分割）になる。
  nginx の `large_client_header_buffers` を広げておく（例：`4 32k`）。
- ログアウトでは、`AWSELBAuthSessionCookie` と `-0` から `-3` をすべて期限切れにしてから、Cognito の `/logout` にリダイレクトする。
  `logout_uri` は Cognito のアプリクライアントの「サインアウト URL」に登録し、ALB の認証の外に置く。

## oauth2-proxy

### 推奨の設定（ID トークンを渡す）

```
--provider=oidc
--oidc-issuer-url=<issuer>
--client-id=<client id>
--client-secret=<client secret>
--redirect-url=https://app.example.com/oauth2/callback
--pass-authorization-header=true      # ID トークンを Authorization: Bearer で渡す
--set-authorization-header=false
--skip-auth-route=GET=^/healthz$
--api-route=^/api/                    # API のパスは 302 でなく 401
```

アプリ側は `BearerJwtSource` を使い、iss と aud（client id）を設定する。
ID トークンの期限（Cognito なら既定 1 時間）が切れると検証に失敗する。
oauth2-proxy に `--cookie-refresh` を設定して、期限より前にトークンを更新させる。

### 署名のないヘッダー（`TrustedHeadersSource`）を使う場合

推奨しない。
使う場合は、次をすべて満たす。

- oauth2-proxy の alpha config の `injectRequestHeaders` で、共有シークレットのヘッダーを付ける。
- アプリに届く経路を oauth2-proxy に限る（ネットワークの制限）。
- 使う版の oauth2-proxy が、クライアントが送ってきた `X-Forwarded-User` などを消してから付け直すことを確かめる。
  `--skip-auth-route` で認証を外したパスでは、クライアントのヘッダーがそのまま届くかもしれない。
  そのパスでは、共有シークレットも付いたままになる可能性がある。
  この組み合わせを実際に送って確かめるまでは、`TrustedHeadersSource` を本番で使わない。

### ログアウト

oauth2-proxy は `/oauth2/sign_out` で自分の cookie を消し、`rd` に指定した URL にリダイレクトする。
IdP のセッションも切る場合は、`rd` に IdP の logout の URL を指定し、そのドメインを `--whitelist-domain` で許可する。

## ALB の JWT 検証（`jwt-validation`）

ALB の JWT 検証は、クライアントが送った JWT を ALB が JWKS で検証し、通ればトークンをそのままアプリに転送する機能である。
機械どうしの通信（M2M）向けで、ALB が署名した独自のヘッダー（`x-amzn-oidc-data` など）は付けない。
アプリ側では、ALB と同じ設定で `BearerJwtSource` を使う。

| ALB の設定 | wristband の設定 |
|---|---|
| `Issuer` | `BearerConfig` の issuer（Laravel では `bearer.issuer`） |
| `JwksEndpoint` | `HttpJwksProvider::fromJwksUri()`（Laravel では `bearer.jwks_uri`） |
| `AdditionalClaims` | `withRequiredClaims()`、scope は `withRequiredScopes()`（Laravel では `bearer.required_claims`、`bearer.required_scopes`） |
| （なし） | audience（`aud` か `client_id`）。wristband では必須 |
| RS256 のみ | `['RS256']` に絞る |

```json
[
  {
    "Type": "jwt-validation",
    "Order": 1,
    "JwtValidationConfig": {
      "JwksEndpoint": "https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_XXXX/.well-known/jwks.json",
      "Issuer": "https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_XXXX",
      "AdditionalClaims": [
        { "Name": "scope", "Format": "space-separated-values", "Values": ["orders/read"] }
      ]
    }
  },
  { "Type": "forward", "Order": 2, "TargetGroupArn": "<target group ARN>" }
]
```

```php
$config = (new BearerConfig(
    'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_XXXX',
    ['svc-a-client-id', 'svc-b-client-id'],
    ['RS256'],
    30,
    'access'
))->withRequiredScopes(['orders/read']);
```

API リファレンスによると、1 つのルールに入れられる認証アクションは、`authenticate-oidc`、`authenticate-cognito`、`jwt-validation` のうち 1 つである。
人のログイン（`authenticate-cognito`）と M2M（`jwt-validation`）を同じアプリで受ける場合は、パスやヘッダーの条件でルールを分ける。

ALB で検証済みでも、アプリでもう一度検証する。
アプリに ALB を通らない経路があった場合や、ALB の設定を誤った場合に、検証されていないトークンを信用しないためである。

ALB の設定項目には audience がない。
同じ issuer が別のクライアントに発行したトークンも ALB を通るので、受け入れるクライアントはアプリ側の audience で絞る。

AWS のドキュメントは、トークンを入れるヘッダーの名前を明記していない。
`Authorization: Bearer` 以外のヘッダーで送る場合は、`BearerJwtSource` のヘッダー名と scheme を合わせる。

## ローカル開発（oauth2-proxy とコンテナの IdP）

本番と同じ `BearerJwtSource` を使う。
ローカル専用の切り替えは要らない。

```
ブラウザ ──> oauth2-proxy :4180 ──> アプリ
                 │
                 └─ OIDC ──> IdP :9229
```

IdP をコンテナで動かすと、ブラウザから見たホスト名（`localhost:9229`）と、コンテナから見たホスト名（`idp:9229`）が違う。
トークンの `iss` はブラウザから見たホスト名になるので、アプリでは次のように分けて設定する。

```dotenv
WRISTBAND_SOURCE=bearer
WRISTBAND_BEARER_ISSUER=http://localhost:9229/<user pool id>          # トークンの iss と完全一致させる
WRISTBAND_BEARER_JWKS_URI=http://idp:9229/<user pool id>/.well-known/jwks.json
WRISTBAND_BEARER_AUDIENCES=<client id>
WRISTBAND_BEARER_TOKEN_USE=id
WRISTBAND_LOGOUT_MODE=oauth2_proxy
WRISTBAND_OAUTH2_PROXY_REDIRECT=http://localhost:9229/logout?client_id=<client id>&logout_uri=http%3A%2F%2Flocalhost%3A4180%2Flogged-out
```

oauth2-proxy 側も同じ問題があるので、discovery を使わず、エンドポイントを個別に指定する。

```
--skip-oidc-discovery=true
--oidc-issuer-url=http://localhost:9229/<user pool id>
--login-url=http://localhost:9229/oauth2/authorize
--redeem-url=http://idp:9229/oauth2/token
--oidc-jwks-url=http://idp:9229/<user pool id>/.well-known/jwks.json
```

issuer と JWKS の正確な URL は、IdP の discovery（`/.well-known/openid-configuration`）の応答で確かめる。
