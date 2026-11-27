<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Clock;

interface ClockInterface
{
    /** Current Unix time in seconds. */
    public function now(): int;
}
