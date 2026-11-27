<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Source;

use Ixbox\Wristband\Exception\TokenMissingException;
use Ixbox\Wristband\Identity;
use Ixbox\Wristband\Request\ProxyRequest;

/**
 * Tries sources in order. Only "no credential" (TokenMissingException) moves
 * on to the next source; any other failure stops the chain, so an invalid
 * ALB token cannot be "rescued" by a weaker source.
 *
 * Prefer a single source in production.
 */
final class ChainSource implements SourceInterface
{
    /** @var list<SourceInterface> */
    private $sources;

    /** @param list<SourceInterface> $sources */
    public function __construct(array $sources)
    {
        if ($sources === []) {
            throw new \InvalidArgumentException('ChainSource needs at least one source.');
        }
        $this->sources = array_values($sources);
    }

    public function authenticate(ProxyRequest $request): Identity
    {
        foreach ($this->sources as $source) {
            try {
                return $source->authenticate($request);
            } catch (TokenMissingException $e) {
                continue;
            }
        }

        throw new TokenMissingException('no_credentials', 'No source found credentials in the request.');
    }
}
