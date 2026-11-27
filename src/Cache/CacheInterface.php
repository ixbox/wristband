<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Cache;

/**
 * The tiny string cache the key providers need. Implementations must not
 * throw: a broken cache should degrade to a miss, not to a failed login.
 */
interface CacheInterface
{
    public function get(string $key): ?string;

    public function set(string $key, string $value, int $ttlSeconds): void;
}
