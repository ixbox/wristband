<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Bearer;

use Ixbox\Wristband\ClaimMap;
use Ixbox\Wristband\Clock\ClockInterface;
use Ixbox\Wristband\Clock\SystemClock;
use Ixbox\Wristband\Exception\AuthenticationException;
use Ixbox\Wristband\Exception\ClaimInvalidException;
use Ixbox\Wristband\Exception\SignatureInvalidException;
use Ixbox\Wristband\Exception\TokenMalformedException;
use Ixbox\Wristband\Exception\TokenMissingException;
use Ixbox\Wristband\Identity;
use Ixbox\Wristband\Jwks\JwksProviderInterface;
use Ixbox\Wristband\Jwt\JwkConverter;
use Ixbox\Wristband\Jwt\Jwt;
use Ixbox\Wristband\Jwt\Signature;
use Ixbox\Wristband\Jwt\TimeClaims;

/**
 * Verifies an OIDC JWT (ID or access token) against a JWKS.
 *
 * Order of checks:
 *  1. structure
 *  2. alg is one of the configured algorithms (never "none" or HS*)
 *  3. iss equals the configured issuer   (before any key fetch)
 *  4. kid present; JWK found; JWK kty/alg/use agree with alg
 *  5. signature
 *  6. exp (required), nbf, iat, with leeway
 *  7. aud contains, or client_id equals, a configured audience
 *  8. token_use, when configured (Cognito)
 */
final class BearerTokenVerifier
{
    /** @var BearerConfig */
    private $config;
    /** @var JwksProviderInterface */
    private $jwks;
    /** @var ClockInterface */
    private $clock;
    /** @var ClaimMap|null */
    private $claimMap;

    public function __construct(BearerConfig $config, JwksProviderInterface $jwks, ?ClockInterface $clock = null, ?ClaimMap $claimMap = null)
    {
        $this->config = $config;
        $this->jwks = $jwks;
        $this->clock = $clock !== null ? $clock : new SystemClock();
        $this->claimMap = $claimMap;
    }

    /**
     * @throws AuthenticationException
     */
    public function verify(string $token): Identity
    {
        if ($token === '') {
            throw new TokenMissingException('header_empty', 'The bearer token is empty.');
        }
        $jwt = Jwt::parse($token, $this->config->maxTokenLength());
        $header = $jwt->header();
        $payload = $jwt->payload();

        $alg = $header['alg'] ?? null;
        if (!is_string($alg) || !in_array($alg, $this->config->algorithms(), true)) {
            throw new TokenMalformedException('alg_not_allowed', 'The token algorithm is not allowed.');
        }
        if (($payload['iss'] ?? null) !== $this->config->issuer()) {
            throw new ClaimInvalidException('issuer_mismatch', 'The token was issued by another issuer.');
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '' || strlen($kid) > 256) {
            throw new TokenMalformedException('invalid_kid', 'The token has no usable kid.');
        }

        $jwk = $this->jwks->getKey($kid);
        self::assertJwkMatches($jwk, $alg);
        if (!Signature::verify($alg, $jwt->signingInput(), $jwt->signature(), JwkConverter::toPem($jwk))) {
            throw new SignatureInvalidException('signature_invalid', 'The token signature is invalid.');
        }

        $now = $this->clock->now();
        TimeClaims::assertNotExpired($payload, $now, $this->config->leeway(), true, 'payload');
        TimeClaims::assertUsableNow($payload, $now, $this->config->leeway());

        if (!$this->audienceMatches($payload)) {
            throw new ClaimInvalidException('audience_mismatch', 'The token was issued for another audience.');
        }
        $tokenUse = $this->config->tokenUse();
        if ($tokenUse !== null && ($payload['token_use'] ?? null) !== $tokenUse) {
            throw new ClaimInvalidException('token_use_mismatch', 'The token_use claim is not "' . $tokenUse . '".');
        }

        return Identity::fromClaims(Identity::SOURCE_BEARER, $payload, $header, $this->claimMap);
    }

    /** @param array<string, mixed> $payload */
    private function audienceMatches(array $payload): bool
    {
        $accepted = $this->config->audiences();
        $aud = $payload['aud'] ?? null;
        foreach (is_array($aud) ? $aud : [$aud] as $value) {
            if (is_string($value) && in_array($value, $accepted, true)) {
                return true;
            }
        }
        // Cognito access tokens carry client_id instead of aud.
        $clientId = $payload['client_id'] ?? null;

        return $aud === null && is_string($clientId) && in_array($clientId, $accepted, true);
    }

    /** @param array<string, mixed> $jwk */
    private static function assertJwkMatches(array $jwk, string $alg): void
    {
        $expectedKty = $alg === Signature::ES256 ? 'EC' : 'RSA';
        if (($jwk['kty'] ?? null) !== $expectedKty) {
            throw new SignatureInvalidException('key_type_mismatch', 'The JWK type does not match the token algorithm.');
        }
        if (isset($jwk['alg']) && $jwk['alg'] !== $alg) {
            throw new SignatureInvalidException('key_alg_mismatch', 'The JWK is registered for another algorithm.');
        }
        if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
            throw new SignatureInvalidException('key_use_mismatch', 'The JWK is not a signature key.');
        }
    }
}
