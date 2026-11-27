<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Source;

use Ixbox\EdgeIdentity\Bearer\BearerTokenVerifier;
use Ixbox\EdgeIdentity\Exception\TokenMissingException;
use Ixbox\EdgeIdentity\Identity;
use Ixbox\EdgeIdentity\Request\ProxyRequest;

/**
 * Reads an OIDC JWT from a header.
 *
 * - oauth2-proxy --pass-authorization-header:  Authorization: Bearer <id_token>  (default)
 * - a header that carries the bare token:      new BearerJwtSource($verifier, 'X-Forwarded-Access-Token', null)
 *
 * An Authorization header with another scheme (e.g. Basic auth in front of a test environment)
 * counts as "no token", not as an error.
 */
final class BearerJwtSource implements SourceInterface
{
    /** @var BearerTokenVerifier */
    private $verifier;
    /** @var string */
    private $headerName;
    /** @var string|null */
    private $scheme;

    public function __construct(BearerTokenVerifier $verifier, string $headerName = 'Authorization', ?string $scheme = 'Bearer')
    {
        $this->verifier = $verifier;
        $this->headerName = $headerName;
        $this->scheme = $scheme !== '' ? $scheme : null;
    }

    public function authenticate(ProxyRequest $request): Identity
    {
        $value = $request->singleHeader($this->headerName);
        if ($this->scheme !== null) {
            $prefix = $this->scheme . ' ';
            if (strncasecmp($value, $prefix, strlen($prefix)) !== 0) {
                throw new TokenMissingException('unsupported_scheme', 'The ' . $this->headerName . ' header does not use the ' . $this->scheme . ' scheme.');
            }
            $value = ltrim(substr($value, strlen($prefix)));
        }

        return $this->verifier->verify($value);
    }
}
