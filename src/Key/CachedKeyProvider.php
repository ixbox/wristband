<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Key;

use Ixbox\Wristband\Cache\CacheInterface;
use Ixbox\Wristband\Exception\KeyFetchFailedException;

/**
 * Caches keys per kid. An ALB key never changes for a given kid, so the TTL
 * can be long. A failed fetch is remembered briefly so a burst of requests
 * does not hammer the key endpoint.
 */
final class CachedKeyProvider implements KeyProviderInterface
{
    private const FAILURE_MARKER = '!failed';

    /** @var KeyProviderInterface */
    private $inner;
    /** @var CacheInterface */
    private $cache;
    /** @var int */
    private $ttl;
    /** @var int */
    private $failureTtl;
    /** @var string */
    private $namespace;
    /** @var array<string, string> */
    private $memory = [];

    /**
     * @param string $namespace distinguishes key sets sharing one cache (e.g. the real endpoint and a mock)
     */
    public function __construct(
        KeyProviderInterface $inner,
        CacheInterface $cache,
        int $ttlSeconds = 604800,
        int $failureTtlSeconds = 10,
        string $namespace = 'alb'
    ) {
        $this->inner = $inner;
        $this->cache = $cache;
        $this->ttl = max(1, $ttlSeconds);
        $this->failureTtl = max(0, $failureTtlSeconds);
        $this->namespace = $namespace;
    }

    public function get(string $kid): string
    {
        if (isset($this->memory[$kid])) {
            return $this->memory[$kid];
        }
        $key = 'alb_key:' . $this->namespace . ':' . $kid;
        $cached = $this->cache->get($key);
        if ($cached === self::FAILURE_MARKER) {
            throw new KeyFetchFailedException('key_fetch_backoff', 'The ALB public key fetch failed recently; not retrying yet.');
        }
        if ($cached !== null) {
            return $this->memory[$kid] = $cached;
        }

        try {
            $pem = $this->inner->get($kid);
        } catch (KeyFetchFailedException $e) {
            if ($this->failureTtl > 0) {
                $this->cache->set($key, self::FAILURE_MARKER, $this->failureTtl);
            }
            throw $e;
        }
        $this->cache->set($key, $pem, $this->ttl);

        return $this->memory[$kid] = $pem;
    }
}
