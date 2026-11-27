<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Cache;

/**
 * Adapts a PSR-16 cache (psr/simple-cache 1, 2 or 3), e.g. Laravel's cache
 * repository or a Symfony/Redis adapter. Keys are hashed so they are always
 * valid PSR-16 keys. Cache errors degrade to misses.
 */
final class Psr16Cache implements CacheInterface
{
    /** @var \Psr\SimpleCache\CacheInterface */
    private $cache;

    public function __construct(\Psr\SimpleCache\CacheInterface $cache)
    {
        $this->cache = $cache;
    }

    public function get(string $key): ?string
    {
        try {
            $value = $this->cache->get(self::key($key));
        } catch (\Throwable $e) {
            return null;
        }

        return is_string($value) ? $value : null;
    }

    public function set(string $key, string $value, int $ttlSeconds): void
    {
        try {
            $this->cache->set(self::key($key), $value, $ttlSeconds);
        } catch (\Throwable $e) {
            // a cache outage must not break authentication
        }
    }

    private static function key(string $key): string
    {
        return 'wristband.' . hash('sha256', $key);
    }
}
