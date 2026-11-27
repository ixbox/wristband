<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Alb;

use Ixbox\EdgeIdentity\Cache\ArrayCache;
use Ixbox\EdgeIdentity\Cache\CacheInterface;
use Ixbox\EdgeIdentity\ClaimMap;
use Ixbox\EdgeIdentity\Clock\ClockInterface;
use Ixbox\EdgeIdentity\Clock\SystemClock;
use Ixbox\EdgeIdentity\Exception\AuthenticationException;
use Ixbox\EdgeIdentity\Exception\ClaimInvalidException;
use Ixbox\EdgeIdentity\Exception\SignatureInvalidException;
use Ixbox\EdgeIdentity\Exception\SignerMismatchException;
use Ixbox\EdgeIdentity\Exception\TokenMalformedException;
use Ixbox\EdgeIdentity\Exception\TokenMissingException;
use Ixbox\EdgeIdentity\Identity;
use Ixbox\EdgeIdentity\Jwt\Jwt;
use Ixbox\EdgeIdentity\Jwt\Signature;
use Ixbox\EdgeIdentity\Jwt\TimeClaims;
use Ixbox\EdgeIdentity\Key\CachedKeyProvider;
use Ixbox\EdgeIdentity\Key\HttpKeyProvider;
use Ixbox\EdgeIdentity\Key\KeyProviderInterface;

/**
 * Verifies the value of the x-amzn-oidc-data header.
 *
 * Order of checks:
 *  1. structure (three base64url segments, padding optional, JSON objects)
 *  2. alg is exactly ES256
 *  3. signer is a configured ALB ARN    (before any key fetch)
 *  4. kid is a UUID                     (before it goes into a URL)
 *  5. ES256 signature with the ALB public key for kid
 *  6. client / iss, when configured
 *  7. exp in header (required) and payload (when present), with leeway
 */
final class AlbTokenVerifier
{
    private const KID_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i';

    /** @var AlbConfig */
    private $config;
    /** @var KeyProviderInterface */
    private $keys;
    /** @var ClockInterface */
    private $clock;
    /** @var ClaimMap|null */
    private $claimMap;

    /**
     * @param KeyProviderInterface|null $keys defaults to the regional ALB endpoint with a per-process cache
     */
    public function __construct(AlbConfig $config, ?KeyProviderInterface $keys = null, ?ClockInterface $clock = null, ?ClaimMap $claimMap = null)
    {
        $this->config = $config;
        $this->keys = $keys !== null ? $keys : self::defaultKeyProvider($config);
        $this->clock = $clock !== null ? $clock : new SystemClock();
        $this->claimMap = $claimMap;
    }

    /**
     * The regional ALB key endpoint behind a cache. Pass a shared cache
     * (Psr16Cache) so keys survive across PHP-FPM requests.
     */
    public static function defaultKeyProvider(AlbConfig $config, ?CacheInterface $cache = null): KeyProviderInterface
    {
        return new CachedKeyProvider(
            HttpKeyProvider::forRegion($config->region()),
            $cache !== null ? $cache : new ArrayCache()
        );
    }

    /**
     * @throws AuthenticationException
     */
    public function verify(string $token): Identity
    {
        if ($token === '') {
            throw new TokenMissingException('header_empty', 'The ALB token is empty.');
        }
        $jwt = Jwt::parse($token, $this->config->maxTokenLength());
        $header = $jwt->header();

        if (($header['alg'] ?? null) !== Signature::ES256) {
            throw new TokenMalformedException('alg_not_allowed', 'ALB tokens must use ES256.');
        }
        $signer = $header['signer'] ?? null;
        if (!is_string($signer) || !in_array($signer, $this->config->signerArns(), true)) {
            throw new SignerMismatchException('signer_mismatch', 'The token was not signed by a configured load balancer.');
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || preg_match(self::KID_PATTERN, $kid) !== 1) {
            throw new TokenMalformedException('invalid_kid', 'The ALB key id is not a UUID.');
        }

        $pem = $this->keys->get($kid);
        if (!Signature::verify(Signature::ES256, $jwt->signingInput(), $jwt->signature(), $pem)) {
            throw new SignatureInvalidException('signature_invalid', 'The ALB token signature is invalid.');
        }

        $payload = $jwt->payload();
        $clientIds = $this->config->clientIds();
        if ($clientIds !== [] && !in_array($header['client'] ?? null, $clientIds, true)) {
            throw new ClaimInvalidException('client_mismatch', 'The token was issued for another client.');
        }
        $issuer = $this->config->issuer();
        if ($issuer !== null) {
            if (($header['iss'] ?? null) !== $issuer || (array_key_exists('iss', $payload) && $payload['iss'] !== $issuer)) {
                throw new ClaimInvalidException('issuer_mismatch', 'The token was issued by another issuer.');
            }
        }

        $now = $this->clock->now();
        TimeClaims::assertNotExpired($header, $now, $this->config->leeway(), true, 'header');
        TimeClaims::assertNotExpired($payload, $now, $this->config->leeway(), false, 'payload');

        return Identity::fromClaims(Identity::SOURCE_ALB, $payload, $header, $this->claimMap);
    }
}
