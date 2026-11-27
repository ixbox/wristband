<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Jwks;

use Ixbox\Wristband\Exception\KeyFetchFailedException;

interface JwksProviderInterface
{
    /**
     * Returns the JWK with this kid.
     *
     * @return array<string, mixed>
     * @throws KeyFetchFailedException when the key is unknown or the JWKS cannot be fetched
     */
    public function getKey(string $kid): array;
}
