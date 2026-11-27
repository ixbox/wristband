<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Key;

use Ixbox\EdgeIdentity\Exception\KeyFetchFailedException;

/** Resolves an ALB key id to its PEM public key. */
interface KeyProviderInterface
{
    /**
     * @throws KeyFetchFailedException
     */
    public function get(string $kid): string;
}
