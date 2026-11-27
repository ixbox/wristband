<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Bearer;

use Ixbox\EdgeIdentity\Exception\ConfigurationException;
use Ixbox\EdgeIdentity\Jwt\Signature;

/**
 * What an OIDC bearer token (e.g. the ID token oauth2-proxy forwards with
 * --pass-authorization-header) must look like to be accepted.
 *
 *     new BearerConfig(
 *         'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_XXXX', // required: exact iss
 *         'app-client-id',          // required: accepted aud / client_id value(s)
 *         ['RS256', 'ES256'],       // accepted algorithms
 *         30,                       // leeway for exp / nbf / iat
 *         'id'                      // optional: Cognito token_use ("id" or "access")
 *     );
 */
final class BearerConfig
{
    /** @var string */
    private $issuer;
    /** @var list<string> */
    private $audiences;
    /** @var list<string> */
    private $algorithms;
    /** @var int */
    private $leeway;
    /** @var string|null */
    private $tokenUse;
    /** @var int */
    private $maxTokenLength = 16384;

    /**
     * @param string|list<string> $audiences
     * @param list<string>        $algorithms
     */
    public function __construct(string $issuer, $audiences, array $algorithms = [Signature::RS256, Signature::ES256], int $leeway = 30, ?string $tokenUse = null)
    {
        if ($issuer === '') {
            throw new ConfigurationException('The issuer is required.');
        }
        $audiences = is_array($audiences) ? $audiences : [$audiences];
        $this->audiences = [];
        foreach ($audiences as $audience) {
            if (!is_string($audience) || $audience === '') {
                throw new ConfigurationException('Each audience must be a non-empty string.');
            }
            $this->audiences[] = $audience;
        }
        if ($this->audiences === []) {
            // Without an audience check any token from the same issuer (for any client) would be accepted.
            throw new ConfigurationException('At least one audience (client id) is required.');
        }
        $this->algorithms = [];
        foreach ($algorithms as $alg) {
            if ($alg !== Signature::RS256 && $alg !== Signature::ES256) {
                throw new ConfigurationException('Unsupported algorithm: ' . (is_string($alg) ? $alg : gettype($alg)));
            }
            $this->algorithms[] = $alg;
        }
        if ($this->algorithms === []) {
            throw new ConfigurationException('At least one algorithm is required.');
        }
        if ($leeway < 0) {
            throw new ConfigurationException('Leeway must not be negative.');
        }
        if ($tokenUse !== null && $tokenUse !== 'id' && $tokenUse !== 'access') {
            throw new ConfigurationException('token_use must be "id", "access" or null.');
        }
        $this->issuer = $issuer;
        $this->leeway = $leeway;
        $this->tokenUse = $tokenUse;
    }

    public function issuer(): string
    {
        return $this->issuer;
    }

    /** @return list<string> */
    public function audiences(): array
    {
        return $this->audiences;
    }

    /** @return list<string> */
    public function algorithms(): array
    {
        return $this->algorithms;
    }

    public function leeway(): int
    {
        return $this->leeway;
    }

    public function tokenUse(): ?string
    {
        return $this->tokenUse;
    }

    public function maxTokenLength(): int
    {
        return $this->maxTokenLength;
    }

    public function withMaxTokenLength(int $bytes): self
    {
        if ($bytes < 256) {
            throw new ConfigurationException('The maximum token length is unreasonably small.');
        }
        $clone = clone $this;
        $clone->maxTokenLength = $bytes;

        return $clone;
    }
}
