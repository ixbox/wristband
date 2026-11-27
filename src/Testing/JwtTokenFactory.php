<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Testing;

use Ixbox\EdgeIdentity\Bearer\BearerConfig;
use Ixbox\EdgeIdentity\Bearer\BearerTokenVerifier;
use Ixbox\EdgeIdentity\Clock\ClockInterface;
use Ixbox\EdgeIdentity\Clock\SystemClock;
use Ixbox\EdgeIdentity\Jwks\StaticJwksProvider;
use Ixbox\EdgeIdentity\Jwt\Base64Url;
use Ixbox\EdgeIdentity\Jwt\Signature;

/**
 * Issues OIDC-style JWTs (unpadded base64url, RS256 or ES256) and the JWKS
 * that verifies them. For BearerJwtSource tests.
 *
 * FOR TESTS ONLY. Never wire this into production code.
 */
final class JwtTokenFactory
{
    public const DEFAULT_ISSUER = 'https://idp.example.test';
    public const DEFAULT_AUDIENCE = 'test-client-id';

    /** @var KeyPair */
    private $key;
    /** @var string */
    private $kid;
    /** @var string */
    private $issuer;
    /** @var string */
    private $audience;
    /** @var ClockInterface */
    private $clock;

    public function __construct(
        string $issuer = self::DEFAULT_ISSUER,
        string $audience = self::DEFAULT_AUDIENCE,
        string $alg = Signature::RS256,
        ?ClockInterface $clock = null,
        string $kid = 'test-key-1'
    ) {
        $this->key = KeyPair::generate($alg);
        $this->kid = $kid;
        $this->issuer = $issuer;
        $this->audience = $audience;
        $this->clock = $clock !== null ? $clock : new SystemClock();
    }

    /**
     * @param array<string, mixed> $claims merged over the default payload (null values remove a claim)
     * @param array<string, mixed> $header merged over the default header (null values remove a member)
     */
    public function issue(array $claims = [], array $header = [], int $ttlSeconds = 300): string
    {
        $now = $this->clock->now();
        $payload = self::merge([
            'iss' => $this->issuer,
            'sub' => 'test-user',
            'aud' => $this->audience,
            'iat' => $now,
            'exp' => $now + $ttlSeconds,
            'email' => 'user@example.com',
            'email_verified' => true,
        ], $claims);
        $head = self::merge(['alg' => $this->key->alg(), 'typ' => 'JWT', 'kid' => $this->kid], $header);

        $input = Base64Url::encode((string) json_encode($head, JSON_UNESCAPED_SLASHES))
            . '.' . Base64Url::encode((string) json_encode($payload, JSON_UNESCAPED_SLASHES));

        return $input . '.' . Base64Url::encode($this->key->sign($input));
    }

    /** @return array{keys: list<array<string, string>>} */
    public function jwks(): array
    {
        return ['keys' => [$this->key->jwk() + ['kid' => $this->kid, 'alg' => $this->key->alg(), 'use' => 'sig']]];
    }

    public function jwksProvider(): StaticJwksProvider
    {
        return new StaticJwksProvider($this->jwks());
    }

    public function issuer(): string
    {
        return $this->issuer;
    }

    public function audience(): string
    {
        return $this->audience;
    }

    public function kid(): string
    {
        return $this->kid;
    }

    public function config(int $leeway = 30, ?string $tokenUse = null): BearerConfig
    {
        return new BearerConfig($this->issuer, $this->audience, [Signature::RS256, Signature::ES256], $leeway, $tokenUse);
    }

    public function verifier(?ClockInterface $clock = null): BearerTokenVerifier
    {
        return new BearerTokenVerifier($this->config(), $this->jwksProvider(), $clock !== null ? $clock : $this->clock);
    }

    /**
     * @param array<string, mixed> $base
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private static function merge(array $base, array $overrides): array
    {
        foreach ($overrides as $name => $value) {
            if ($value === null) {
                unset($base[$name]);
            } else {
                $base[$name] = $value;
            }
        }

        return $base;
    }
}
