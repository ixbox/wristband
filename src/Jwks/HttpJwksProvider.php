<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Jwks;

use Ixbox\EdgeIdentity\Cache\ArrayCache;
use Ixbox\EdgeIdentity\Cache\CacheInterface;
use Ixbox\EdgeIdentity\Clock\ClockInterface;
use Ixbox\EdgeIdentity\Clock\SystemClock;
use Ixbox\EdgeIdentity\Exception\ConfigurationException;
use Ixbox\EdgeIdentity\Exception\KeyFetchFailedException;
use Ixbox\EdgeIdentity\Http\HttpClientInterface;
use Ixbox\EdgeIdentity\Http\HttpException;
use Ixbox\EdgeIdentity\Http\NativeHttpClient;

/**
 * Fetches a JWKS over HTTP, either from a fixed jwks_uri or through OIDC
 * discovery, and caches it.
 *
 * - Keys are cached for $ttlSeconds.
 * - An unknown kid triggers a refetch (key rotation), at most once per
 *   $refreshCooldownSeconds, shared through the cache across processes.
 * - When a refetch fails, the previously cached keys stay in use.
 *
 * Use fromJwksUri() when the issuer's public host is not reachable from the
 * app (e.g. an IdP in Docker: the browser sees localhost:9229, the app must
 * use idp:9229). The issuer claim is still checked against the configured
 * issuer string by BearerTokenVerifier.
 */
final class HttpJwksProvider implements JwksProviderInterface
{
    private const MAX_BYTES = 1048576;
    private const INITIAL_FAILURE_BACKOFF = 10;

    /** @var string|null */
    private $jwksUri;
    /** @var string|null */
    private $discoveryUrl;
    /** @var HttpClientInterface */
    private $http;
    /** @var CacheInterface */
    private $cache;
    /** @var ClockInterface */
    private $clock;
    /** @var int */
    private $ttl;
    /** @var int */
    private $cooldown;
    /** @var float */
    private $timeout;
    /** @var array{fetched_at: int, keys: array<string, array<string, mixed>>}|null */
    private $memory;

    private function __construct(
        ?string $jwksUri,
        ?string $discoveryUrl,
        ?HttpClientInterface $http,
        ?CacheInterface $cache,
        int $ttlSeconds,
        int $refreshCooldownSeconds,
        float $timeoutSeconds,
        ?ClockInterface $clock
    ) {
        $this->jwksUri = $jwksUri;
        $this->discoveryUrl = $discoveryUrl;
        $this->http = $http !== null ? $http : new NativeHttpClient();
        $this->clock = $clock !== null ? $clock : new SystemClock();
        $this->cache = $cache !== null ? $cache : new ArrayCache($this->clock);
        $this->ttl = max(1, $ttlSeconds);
        $this->cooldown = max(0, $refreshCooldownSeconds);
        $this->timeout = $timeoutSeconds;
    }

    public static function fromJwksUri(
        string $jwksUri,
        ?HttpClientInterface $http = null,
        ?CacheInterface $cache = null,
        int $ttlSeconds = 3600,
        int $refreshCooldownSeconds = 60,
        float $timeoutSeconds = 2.0,
        ?ClockInterface $clock = null
    ): self {
        self::assertUrl($jwksUri);

        return new self($jwksUri, null, $http, $cache, $ttlSeconds, $refreshCooldownSeconds, $timeoutSeconds, $clock);
    }

    /** Discovery at {issuer}/.well-known/openid-configuration. */
    public static function fromIssuer(
        string $issuer,
        ?HttpClientInterface $http = null,
        ?CacheInterface $cache = null,
        int $ttlSeconds = 3600,
        int $refreshCooldownSeconds = 60,
        float $timeoutSeconds = 2.0,
        ?ClockInterface $clock = null
    ): self {
        return self::fromDiscoveryUrl(
            rtrim($issuer, '/') . '/.well-known/openid-configuration',
            $http,
            $cache,
            $ttlSeconds,
            $refreshCooldownSeconds,
            $timeoutSeconds,
            $clock
        );
    }

    public static function fromDiscoveryUrl(
        string $discoveryUrl,
        ?HttpClientInterface $http = null,
        ?CacheInterface $cache = null,
        int $ttlSeconds = 3600,
        int $refreshCooldownSeconds = 60,
        float $timeoutSeconds = 2.0,
        ?ClockInterface $clock = null
    ): self {
        self::assertUrl($discoveryUrl);

        return new self(null, $discoveryUrl, $http, $cache, $ttlSeconds, $refreshCooldownSeconds, $timeoutSeconds, $clock);
    }

    public function getKey(string $kid): array
    {
        $state = $this->load();
        if ($state !== null && isset($state['keys'][$kid])) {
            return $state['keys'][$kid];
        }

        $now = $this->clock->now();
        $lastAttempt = $this->lastAttempt();
        if ($state !== null) {
            // Known JWKS but unknown kid: refetch for rotation, rate-limited.
            $since = max($state['fetched_at'], $lastAttempt !== null ? $lastAttempt : 0);
            if ($now - $since < $this->cooldown) {
                throw new KeyFetchFailedException('unknown_kid', 'The JWKS has no key with this kid (refresh is rate-limited).');
            }
        } elseif ($lastAttempt !== null && $now - $lastAttempt < min($this->cooldown, self::INITIAL_FAILURE_BACKOFF)) {
            // Nothing cached and the last fetch failed: back off briefly.
            throw new KeyFetchFailedException('jwks_fetch_backoff', 'Fetching the JWKS failed recently; not retrying yet.');
        }

        $this->cache->set($this->cacheKey('attempt'), (string) $now, max(1, $this->cooldown));
        $keys = $this->fetch();
        $state = ['fetched_at' => $now, 'keys' => $keys];
        $this->memory = $state;
        $this->cache->set($this->cacheKey('jwks'), (string) json_encode($state), $this->ttl);

        if (!isset($keys[$kid])) {
            throw new KeyFetchFailedException('unknown_kid', 'The JWKS has no key with this kid.');
        }

        return $keys[$kid];
    }

    /** @return array{fetched_at: int, keys: array<string, array<string, mixed>>}|null */
    private function load(): ?array
    {
        if ($this->memory !== null && $this->clock->now() - $this->memory['fetched_at'] < $this->ttl) {
            return $this->memory;
        }
        $raw = $this->cache->get($this->cacheKey('jwks'));
        if ($raw === null) {
            return null;
        }
        $state = json_decode($raw, true);
        if (!is_array($state) || !isset($state['fetched_at'], $state['keys']) || !is_int($state['fetched_at']) || !is_array($state['keys'])) {
            return null;
        }

        /** @var array{fetched_at: int, keys: array<string, array<string, mixed>>} $state */
        return $this->memory = $state;
    }

    private function lastAttempt(): ?int
    {
        $raw = $this->cache->get($this->cacheKey('attempt'));

        return $raw !== null && ctype_digit($raw) ? (int) $raw : null;
    }

    /** @return array<string, array<string, mixed>> */
    private function fetch(): array
    {
        $jwksUri = $this->jwksUri !== null ? $this->jwksUri : $this->discoverJwksUri();
        $document = $this->getJson($jwksUri, 'jwks');
        if (!isset($document['keys']) || !is_array($document['keys'])) {
            throw new KeyFetchFailedException('invalid_jwks', 'The JWKS document has no "keys" array.');
        }

        return JwksDocument::index($document);
    }

    private function discoverJwksUri(): string
    {
        $key = $this->cacheKey('jwks_uri');
        $cached = $this->cache->get($key);
        if ($cached !== null) {
            return $cached;
        }
        $config = $this->getJson((string) $this->discoveryUrl, 'discovery');
        if (!isset($config['jwks_uri']) || !is_string($config['jwks_uri'])) {
            throw new KeyFetchFailedException('invalid_discovery', 'The discovery document has no jwks_uri.');
        }
        self::assertUrl($config['jwks_uri']);
        $this->cache->set($key, $config['jwks_uri'], $this->ttl);

        return $config['jwks_uri'];
    }

    /** @return array<string, mixed> */
    private function getJson(string $url, string $what): array
    {
        try {
            $response = $this->http->get($url, $this->timeout, self::MAX_BYTES);
        } catch (HttpException $e) {
            throw new KeyFetchFailedException($what . '_fetch_error', 'Fetching the ' . $what . ' document failed.', $e);
        }
        if ($response->status() !== 200) {
            throw new KeyFetchFailedException($what . '_fetch_status', 'Fetching the ' . $what . ' document returned HTTP ' . $response->status() . '.');
        }
        $data = json_decode($response->body(), true);
        if (!is_array($data)) {
            throw new KeyFetchFailedException('invalid_' . $what, 'The ' . $what . ' document is not JSON.');
        }

        return $data;
    }

    private function cacheKey(string $what): string
    {
        return 'jwks:' . $what . ':' . ($this->jwksUri !== null ? $this->jwksUri : (string) $this->discoveryUrl);
    }

    private static function assertUrl(string $url): void
    {
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if ($scheme !== 'https' && $scheme !== 'http') {
            throw new ConfigurationException('The JWKS / discovery URL must be http(s): ' . $url);
        }
    }
}
