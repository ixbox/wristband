# ixbox/wristband

認証を前段（ALB、oauth2-proxy など）に任せた PHP アプリで、前段が付けたヘッダーを検証してユーザーを特定するライブラリ。
名前は、入口で付けてもらい、中では見せるだけで通れる入場リストバンドに由来する。

- PHP 7.2 から 8.x で動く。
  依存は `ext-openssl`、`ext-json`、Symfony の polyfill（`polyfill-php80`、`polyfill-ctype`）だけで、JWT ライブラリにもフレームワークにも依存しない。
- ALB の `x-amzn-oidc-data`（ES256）、OIDC の JWT（RS256、ES256。oauth2-proxy の `--pass-authorization-header` など）、oauth2-proxy の署名のないヘッダーの 3 種類を、共通の `Identity` に変換する。
- Laravel から使う場合は、guard を提供する `ixbox/laravel-wristband` を使う。
- 前段（ALB、Cognito、oauth2-proxy）の設定例と注意点は [docs/edge-setup.md](docs/edge-setup.md) にある。

## インストール

```bash
composer require ixbox/wristband
```

## 使い方

### ALB（`x-amzn-oidc-data`）

```php
use Ixbox\Wristband\Alb\AlbConfig;
use Ixbox\Wristband\Alb\AlbTokenVerifier;

$verifier = new AlbTokenVerifier(new AlbConfig(
    'arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:loadbalancer/app/xxx/yyy', // 必須: signer
    'ap-northeast-1',          // 省略すると signer の ARN から求める
    'cognito-app-client-id',   // 任意: header の client の期待値
    30                         // exp の許容誤差（秒）
));

$identity = $verifier->verify($headerValue); // 失敗すると AuthenticationException の下位の例外
$identity->sub();
$identity->email();
$identity->username();
$identity->groups();       // cognito:groups
$identity->claims();
$identity->header();       // signer、kid、iss、client、exp
```

ALB が複数ある場合は、signer を配列で渡す。
公開鍵は既定で `https://public-keys.auth.elb.{region}.amazonaws.com/{kid}` から取得し、プロセス内のメモリにキャッシュする。
PHP-FPM ではリクエストごとにメモリが消えるので、共有のキャッシュを渡す（後述の「公開鍵と JWKS のキャッシュ」）。

### リクエストから読む（source）

ヘッダーの取り出しと検証をまとめたものが source である。
どの source も `ProxyRequest` を受け取り、`Identity` を返す。

```php
use Ixbox\Wristband\Request\ProxyRequest;
use Ixbox\Wristband\Source\AlbOidcDataSource;

$source = new AlbOidcDataSource($verifier);

$identity = $source->authenticate(ProxyRequest::fromGlobals());              // $_SERVER
$identity = $source->authenticate(ProxyRequest::fromHttpFoundation($request)); // Symfony HttpFoundation、Laravel
$identity = $source->authenticate(ProxyRequest::fromPsr7($serverRequest));    // PSR-7（psr/http-message が必要）
$identity = $source->authenticate(ProxyRequest::fromArray(['x-amzn-oidc-data' => $value]));
```

| source | 前段 | 読むヘッダー | 検証 |
|---|---|---|---|
| `AlbOidcDataSource` | ALB | `x-amzn-oidc-data` | ES256。signer は必須、client と iss は任意 |
| `BearerJwtSource` | oauth2-proxy、API Gateway など | `Authorization: Bearer <JWT>`（ヘッダー名と scheme は変更できる） | JWKS（RS256、ES256）。iss と aud（または client_id）は必須。token_use は任意 |
| `TrustedHeadersSource` | oauth2-proxy | `X-Forwarded-User` などの署名のないヘッダー | 共有シークレットのヘッダー、送信元 IP の許可リスト、またはその両方。推奨しない |
| `ChainSource` | 複数 | 各 source のヘッダー | 前の source が「資格情報なし」のときだけ次を試す |

`x-amzn-oidc-identity` と `x-amzn-oidc-accesstoken` は署名がないので、読む API を用意していない。

### oauth2-proxy の ID トークン（`BearerJwtSource`）

oauth2-proxy に `--pass-authorization-header=true` を付けると、ID トークンが `Authorization: Bearer` で届く。

```php
use Ixbox\Wristband\Bearer\BearerConfig;
use Ixbox\Wristband\Bearer\BearerTokenVerifier;
use Ixbox\Wristband\Jwks\HttpJwksProvider;
use Ixbox\Wristband\Source\BearerJwtSource;

$config = new BearerConfig(
    'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_XXXX', // iss（完全一致）
    'app-client-id',          // aud または client_id。複数なら配列
    ['RS256', 'ES256'],
    30,
    'id'                      // Cognito のみ: token_use
);

$jwks = HttpJwksProvider::fromIssuer($config->issuer(), null, $cache);
// アプリから issuer のホストに届かない場合（コンテナで動かす IdP など）は、JWKS の URL を直接指定する。
$jwks = HttpJwksProvider::fromJwksUri('http://idp:9229/.well-known/jwks.json', null, $cache);

$source = new BearerJwtSource(new BearerTokenVerifier($config, $jwks));
```

JWKS は kid ごとに引く。
知らない kid が来たら JWKS を取り直すが、その間隔は `refreshCooldownSeconds`（既定 60 秒）以上空ける。
取り直しに失敗した場合は、キャッシュ済みの鍵を使い続ける。

`Authorization` が `Basic` などの別の scheme のときは「資格情報なし」として扱う（前段の Basic 認証と共存できる）。

### oauth2-proxy の署名のないヘッダー（`TrustedHeadersSource`）

`--pass-user-headers` や `--set-xauthrequest` で付くヘッダーを、そのまま信用する。
署名がないので、アプリに直接届く経路があれば、誰でも任意のユーザーになりすませる。
可能なら `BearerJwtSource` を使う。

```php
use Ixbox\Wristband\Source\TrustedHeadersConfig;
use Ixbox\Wristband\Source\TrustedHeadersSource;

$source = new TrustedHeadersSource(new TrustedHeadersConfig([
    'preset'               => 'x-forwarded',          // または 'x-auth-request'
    'shared_secret_header' => 'X-Edge-Auth-Secret',   // oauth2-proxy の injectRequestHeaders で付ける
    'shared_secret'        => getenv('EDGE_AUTH_SECRET'), // 16 文字以上
    'trusted_proxies'      => ['10.0.0.0/8'],         // 任意。シークレットと併用できる
]));
```

共有シークレットと送信元 IP の許可リストのどちらも設定しないと、`ConfigurationException` になる。
送信元 IP は `REMOTE_ADDR` で判定する。
nginx の `real_ip` で `REMOTE_ADDR` をクライアントの IP に書き換えている場合、許可リストは機能しないので、共有シークレットを使う。

### Identity

| メソッド | 内容 |
|---|---|
| `source()` | `alb`、`bearer`、`trusted_headers` |
| `sub()` | 必須。ない場合は検証の時点で `TokenMalformedException` |
| `email()`、`emailVerified()` | `emailVerified()` は IdP が明示した場合だけ true か false。不明なら null |
| `username()` | `cognito:username`、`username`、`preferred_username` の順に探す |
| `groups()` | `cognito:groups`、`groups` の順に探す。文字列ならカンマで分ける |
| `claims()`、`claim($name)`、`header()` | 生の値 |
| `issuer()`、`expiresAt()` | payload と header から求める |

どの claim を使うかは `ClaimMap` で変えられる（Entra ID の `oid` と `upn` など）。

## 例外

失敗はすべて `Ixbox\Wristband\Exception\AuthenticationException` の下位の例外になる。
クラスで分類し、`reason()` で詳細を返す。
メッセージにトークンそのものは含めない。

| クラス | 意味 | 主な `reason()` |
|---|---|---|
| `TokenMissingException` | 資格情報がない。未ログインとして扱う | `header_missing`、`unsupported_scheme`、`no_credentials` |
| `TokenMalformedException` | 形式の誤り | `invalid_format`、`too_long`、`multiple_headers`、`alg_not_allowed`、`invalid_kid`、`exp_missing`、`subject_missing` |
| `SignatureInvalidException` | 署名が合わない | `signature_invalid`、`key_type_mismatch` |
| `SignerMismatchException` | 設定外の ALB が署名した | `signer_mismatch` |
| `ClaimInvalidException` | client、iss、aud、token_use、nbf、iat が合わない | `client_mismatch`、`issuer_mismatch`、`audience_mismatch`、`not_yet_valid` |
| `ExpiredException` | 期限切れ | `expired` |
| `KeyFetchFailedException` | 公開鍵や JWKS を取得できない | `key_fetch_status`、`key_fetch_backoff`、`unknown_kid`、`jwks_fetch_error` |
| `UntrustedRequestException` | 署名のないヘッダーが信用できない経路から届いた | `shared_secret_mismatch`、`untrusted_peer` |

設定の誤りは `ConfigurationException`（`InvalidArgumentException` の下位）で、認証の失敗とは区別する。

## 検証の仕様

ALB のトークンは、次の順に確かめる。

1. 3 つに分かれた base64url であること。パディングはあってもなくてもよい（ALB は付ける）。
2. `alg` が `ES256` であること。`none`、`HS*`、`RS*` は拒否する。
3. `signer` が設定した ARN のどれかであること。公開鍵を取得する前に確かめる。
4. `kid` が UUID の形式であること。URL に埋め込む前に確かめる。
5. ES256 の署名（R‖S の 64 バイト）を、kid の公開鍵で検証する。
6. 設定していれば、`client` と `iss` を確かめる。
7. header の `exp`（必須）と payload の `exp`（あれば）を、許容誤差つきで確かめる。

OIDC の JWT は、alg の許可リスト、iss（鍵を取得する前）、kid と JWK の種類の一致、署名、`exp`（必須）、`nbf`、`iat`、aud または client_id、token_use の順に確かめる。

入口では、同じヘッダーが複数あるものと、16KB を超えるものを拒否する。
PHP-FPM は重複したヘッダーを `a, b` の形に連結するが、カンマは base64url の文字ではないので、形式の検査で拒否される。

## 公開鍵と JWKS のキャッシュ

`CacheInterface`（`get` と `set` だけの小さなインターフェース）を渡す。

- `ArrayCache`：プロセス内のメモリ。既定で使う。
- `Psr16Cache`：PSR-16 のキャッシュ（Laravel の Cache Repository、Symfony Cache など）を包む。

PSR-16 のキャッシュがない環境では、`CacheInterface` を自分で実装する。

```php
final class RedisKeyCache implements \Ixbox\Wristband\Cache\CacheInterface
{
    private $redis;

    public function __construct(\Redis $redis) { $this->redis = $redis; }

    public function get(string $key): ?string
    {
        try {
            $value = $this->redis->get('wristband:' . sha1($key));
        } catch (\Throwable $e) {
            return null;
        }
        return is_string($value) ? $value : null;
    }

    public function set(string $key, string $value, int $ttlSeconds): void
    {
        try {
            $this->redis->setex('wristband:' . sha1($key), $ttlSeconds, $value);
        } catch (\Throwable $e) {
        }
    }
}

$keys = AlbTokenVerifier::defaultKeyProvider($config, new RedisKeyCache($redis));
$verifier = new AlbTokenVerifier($config, $keys);
```

ALB の公開鍵は kid ごとに変わらないので、既定で 7 日保持する。
取得に失敗した kid は 10 秒間失敗として覚え、その間は取りに行かない。
キャッシュの障害は「キャッシュになし」として扱い、認証そのものは止めない。

公開鍵の URL は差し替えられる（検証用の環境やモックの配布元を使う場合）。

```php
use Ixbox\Wristband\Key\CachedKeyProvider;
use Ixbox\Wristband\Key\HttpKeyProvider;

$keys = new CachedKeyProvider(new HttpKeyProvider('http://localhost:8080/keys/{kid}'), $cache, 604800, 10, 'local');
```

## ログアウト

フレームワークに依存しないよう、値だけを返す。

```php
use Ixbox\Wristband\Logout\AlbLogout;
use Ixbox\Wristband\Logout\Oauth2ProxyLogout;

AlbLogout::cookiesToExpire();   // AWSELBAuthSessionCookie と -0 から -3
AlbLogout::cognitoLogoutUrl('auth.example.com', $clientId, 'https://app.example.com/logged-out');
Oauth2ProxyLogout::signOutUrl($idpLogoutUrl); // /oauth2/sign_out?rd=...
```

ALB の場合は、返された cookie をすべて期限切れにしてから、Cognito の `/logout` にリダイレクトする。
`logout_uri` に指定するページは、ALB の認証の外に置く。

## テスト用の道具

`Ixbox\Wristband\Testing` は、このライブラリを使うアプリのテストで使う。
本番のコードからは使わない。

```php
use Ixbox\Wristband\Clock\FrozenClock;
use Ixbox\Wristband\Testing\AlbTokenFactory;
use Ixbox\Wristband\Testing\JwtTokenFactory;

$alb = new AlbTokenFactory();                 // P-256 の鍵を生成する
$token = $alb->issue(['email' => 'taro@example.com'], [], 120);
$verifier = $alb->verifier();                 // signer、client、StaticKeyProvider を設定済み
$alb->keyProvider();                          // 自前の verifier に渡す場合

$jwt = new JwtTokenFactory('https://idp.example.test', 'client-id', 'RS256');
$jwt->issue(['sub' => 'u-1']);
$jwt->jwks();                                 // JWKS の文書
$jwt->jwksProvider();
```

`AlbTokenFactory` は、ALB と同じ形式（パディング付きの base64url、R‖S の署名、header の `signer`、`kid`、`client`、`exp`）でトークンを作る。
`issue()` の引数に null を渡すと、その claim を消せる。
時刻は `FrozenClock` で固定できる。

## 開発

```bash
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse
```

## ライセンス

MIT（[LICENSE](LICENSE)）
