<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Clock;

final class SystemClock implements ClockInterface
{
    public function now(): int
    {
        return time();
    }
}
