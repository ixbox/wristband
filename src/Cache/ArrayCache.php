<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Cache;

use Ixbox\EdgeIdentity\Clock\ClockInterface;
use Ixbox\EdgeIdentity\Clock\SystemClock;

/** Per-process memory cache. */
final class ArrayCache implements CacheInterface
{
    /** @var array<string, array{0: string, 1: int}> */
    private $items = [];
    /** @var ClockInterface */
    private $clock;

    public function __construct(?ClockInterface $clock = null)
    {
        $this->clock = $clock !== null ? $clock : new SystemClock();
    }

    public function get(string $key): ?string
    {
        if (!isset($this->items[$key])) {
            return null;
        }
        list($value, $expiresAt) = $this->items[$key];
        if ($this->clock->now() >= $expiresAt) {
            unset($this->items[$key]);

            return null;
        }

        return $value;
    }

    public function set(string $key, string $value, int $ttlSeconds): void
    {
        $this->items[$key] = [$value, $this->clock->now() + $ttlSeconds];
    }
}
