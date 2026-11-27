<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Clock;

interface ClockInterface
{
    /** Current Unix time in seconds. */
    public function now(): int;
}
