<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Clock;

/**
 * A clock that only moves when told to. For tests and for verifying
 * recorded tokens (fixtures) whose exp is in the past.
 */
final class FrozenClock implements ClockInterface
{
    /** @var int */
    private $now;

    public function __construct(int $now)
    {
        $this->now = $now;
    }

    public function now(): int
    {
        return $this->now;
    }

    public function set(int $now): void
    {
        $this->now = $now;
    }

    public function advance(int $seconds): void
    {
        $this->now += $seconds;
    }
}
