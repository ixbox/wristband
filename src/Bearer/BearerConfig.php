<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Bearer;

use Ixbox\Wristband\Exception\ConfigurationException;
use Ixbox\Wristband\Jwt\ClaimValues;
use Ixbox\Wristband\Jwt\Signature;

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
    /** @var list<string> */
    private $requiredScopes = [];
    /** @var array<string, list<string>> */
    private $requiredClaims = [];

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

    /** @return list<string> */
    public function requiredScopes(): array
    {
        return $this->requiredScopes;
    }

    /** @return array<string, list<string>> */
    public function requiredClaims(): array
    {
        return $this->requiredClaims;
    }

    /**
     * Scopes that must all be present in "scope" (space-separated) or "scp".
     *
     * @param list<string> $scopes
     */
    public function withRequiredScopes(array $scopes): self
    {
        $clone = clone $this;
        $clone->requiredScopes = [];
        foreach ($scopes as $scope) {
            if (!is_string($scope) || trim($scope) === '' || preg_match('/\s/', trim($scope)) === 1) {
                throw new ConfigurationException('Each required scope must be a single non-empty word.');
            }
            $clone->requiredScopes[] = trim($scope);
        }

        return $clone;
    }

    /**
     * Claims that must have one of the given values, like the ALB
     * jwt-validation "AdditionalClaims". A value may be a string, int or
     * bool, or a list of them (any one matches). When the claim in the token
     * is an array, one of its elements must match.
     *
     *     ->withRequiredClaims(['client_id' => ['svc-a', 'svc-b'], 'tenant' => 'acme'])
     *
     * @param array<string, string|int|bool|list<string|int|bool>> $claims
     */
    public function withRequiredClaims(array $claims): self
    {
        $clone = clone $this;
        $clone->requiredClaims = [];
        foreach ($claims as $name => $values) {
            if (!is_string($name) || $name === '') {
                throw new ConfigurationException('Required claim names must be non-empty strings.');
            }
            $allowed = [];
            foreach (is_array($values) ? $values : [$values] as $value) {
                $normalized = ClaimValues::normalize($value);
                if ($normalized === null) {
                    throw new ConfigurationException('Required claim values must be strings, integers or booleans: ' . $name);
                }
                $allowed[] = $normalized;
            }
            if ($allowed === []) {
                throw new ConfigurationException('Required claim "' . $name . '" has no allowed values.');
            }
            $clone->requiredClaims[$name] = $allowed;
        }

        return $clone;
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
