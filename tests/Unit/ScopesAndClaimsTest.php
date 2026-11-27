<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Tests\Unit;

use Ixbox\Wristband\Bearer\BearerTokenVerifier;
use Ixbox\Wristband\Clock\FrozenClock;
use Ixbox\Wristband\Exception\ClaimInvalidException;
use Ixbox\Wristband\Exception\ConfigurationException;
use Ixbox\Wristband\Identity;
use Ixbox\Wristband\Testing\AlbTokenFactory;
use Ixbox\Wristband\Testing\JwtTokenFactory;
use PHPUnit\Framework\TestCase;

final class ScopesAndClaimsTest extends TestCase
{
    /** @var FrozenClock */
    private $clock;
    /** @var JwtTokenFactory */
    private $jwt;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock(1800000000);
        $this->jwt = new JwtTokenFactory(JwtTokenFactory::DEFAULT_ISSUER, JwtTokenFactory::DEFAULT_AUDIENCE, 'RS256', $this->clock);
    }

    /**
     * A Cognito client-credentials access token: no aud, client_id, space-separated scope.
     *
     * @param array<string, mixed> $claims
     */
    private function m2mToken(array $claims = []): string
    {
        return $this->jwt->issue($claims + [
            'aud' => null,
            'email' => null,
            'email_verified' => null,
            'sub' => 'svc-client',
            'client_id' => JwtTokenFactory::DEFAULT_AUDIENCE,
            'token_use' => 'access',
            'scope' => 'orders/read orders/write',
        ]);
    }

    /**
     * @param list<string>                                         $scopes
     * @param array<string, string|int|bool|list<string|int|bool>> $claims
     */
    private function verifier(array $scopes = [], array $claims = []): BearerTokenVerifier
    {
        $config = $this->jwt->config(30, 'access')->withRequiredScopes($scopes)->withRequiredClaims($claims);

        return new BearerTokenVerifier($config, $this->jwt->jwksProvider(), $this->clock);
    }

    public function testIdentityExposesScopesAndClient(): void
    {
        $identity = $this->verifier()->verify($this->m2mToken());

        self::assertSame(['orders/read', 'orders/write'], $identity->scopes());
        self::assertTrue($identity->hasScope('orders/read'));
        self::assertFalse($identity->hasScope('orders'));
        self::assertSame(JwtTokenFactory::DEFAULT_AUDIENCE, $identity->clientId());
        self::assertNull($identity->email());
        self::assertSame('svc-client', $identity->sub());
    }

    public function testScpClaimAsArrayOrString(): void
    {
        self::assertSame(['a', 'b'], Identity::fromClaims('bearer', ['sub' => 'x', 'scp' => ['a', 'b']])->scopes());
        self::assertSame(['a', 'b'], Identity::fromClaims('bearer', ['sub' => 'x', 'scp' => 'a  b a'])->scopes());
        self::assertSame([], Identity::fromClaims('bearer', ['sub' => 'x'])->scopes());
    }

    public function testClientIdFallbacks(): void
    {
        self::assertSame('p', Identity::fromClaims('bearer', ['sub' => 'x', 'azp' => 'p'])->clientId());
        self::assertSame('o', Identity::fromClaims('bearer', ['sub' => 'x', 'cid' => 'o'])->clientId());
        self::assertNull(Identity::fromClaims('bearer', ['sub' => 'x'])->clientId());

        $alb = new AlbTokenFactory(AlbTokenFactory::DEFAULT_SIGNER, 'alb-client', AlbTokenFactory::DEFAULT_ISSUER, $this->clock);
        self::assertSame('alb-client', $alb->verifier()->verify($alb->issue())->clientId());
    }

    public function testRequiredScopes(): void
    {
        self::assertInstanceOf(Identity::class, $this->verifier(['orders/read'])->verify($this->m2mToken()));
        self::assertInstanceOf(Identity::class, $this->verifier(['orders/read', 'orders/write'])->verify($this->m2mToken()));

        foreach ([['orders/admin'], ['orders/read', 'orders/admin']] as $required) {
            try {
                $this->verifier($required)->verify($this->m2mToken());
                self::fail('Expected scope_missing');
            } catch (ClaimInvalidException $e) {
                self::assertSame('scope_missing', $e->reason());
            }
        }
    }

    public function testRequiredClaims(): void
    {
        $token = $this->m2mToken(['tenant' => 'acme', 'tier' => 3, 'beta' => true, 'groups' => ['ops', 'dev']]);

        self::assertInstanceOf(Identity::class, $this->verifier([], [
            'tenant' => 'acme',
            'tier' => [2, 3],
            'beta' => true,
            'groups' => 'dev',
            'client_id' => [JwtTokenFactory::DEFAULT_AUDIENCE, 'other'],
        ])->verify($token));

        foreach ([['tenant' => 'other'], ['tier' => '4'], ['beta' => false], ['groups' => 'admin'], ['missing' => 'x']] as $required) {
            try {
                $this->verifier([], $required)->verify($token);
                self::fail('Expected claim_mismatch for ' . (string) json_encode($required));
            } catch (ClaimInvalidException $e) {
                self::assertSame('claim_mismatch', $e->reason());
            }
        }
    }

    public function testConfigValidation(): void
    {
        $config = $this->jwt->config();
        foreach ([
            static function () use ($config) {
                $config->withRequiredScopes(['two words']);
            },
            static function () use ($config) {
                $config->withRequiredScopes(['']);
            },
            static function () use ($config) {
                $config->withRequiredClaims(['x' => []]);
            },
            static function () use ($config) {
                // A float is not an allowed claim value (decoded from JSON, as config often is).
                $config->withRequiredClaims(self::untyped(['x' => 1.5]));
            },
        ] as $i => $invalid) {
            try {
                $invalid();
                self::fail('Expected ConfigurationException #' . $i);
            } catch (ConfigurationException $e) {
                self::assertNotSame('', $e->getMessage());
            }
        }
        self::assertSame(['tier' => ['3']], $config->withRequiredClaims(['tier' => 3])->requiredClaims());
    }

    /**
     * Hands invalid input to the API the way untyped configuration would.
     *
     * @param array<string, mixed> $value
     * @return array<string, mixed>
     */
    private static function untyped(array $value): array
    {
        return $value;
    }
}
