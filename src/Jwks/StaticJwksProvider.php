<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Jwks;

use Ixbox\Wristband\Exception\KeyFetchFailedException;

/** A fixed JWKS document, for tests and pinned keys. */
final class StaticJwksProvider implements JwksProviderInterface
{
    /** @var array<string, array<string, mixed>> */
    private $keys = [];

    /** @param array<string, mixed> $jwks a JWKS document: ['keys' => [...]] */
    public function __construct(array $jwks)
    {
        $this->keys = JwksDocument::index($jwks);
    }

    public function getKey(string $kid): array
    {
        if (!isset($this->keys[$kid])) {
            throw new KeyFetchFailedException('unknown_kid', 'The JWKS has no key with this kid.');
        }

        return $this->keys[$kid];
    }
}
