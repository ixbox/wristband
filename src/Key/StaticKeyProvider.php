<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Key;

use Ixbox\Wristband\Exception\KeyFetchFailedException;

/** Fixed kid => PEM map, for tests and local setups. */
final class StaticKeyProvider implements KeyProviderInterface
{
    /** @var array<string, string> */
    private $keys;

    /** @param array<string, string> $keys kid => PEM */
    public function __construct(array $keys)
    {
        $this->keys = $keys;
    }

    public function get(string $kid): string
    {
        if (!isset($this->keys[$kid])) {
            throw new KeyFetchFailedException('unknown_kid', 'No public key is configured for this kid.');
        }

        return $this->keys[$kid];
    }

    public function with(string $kid, string $pem): self
    {
        $clone = clone $this;
        $clone->keys[$kid] = $pem;

        return $clone;
    }
}
