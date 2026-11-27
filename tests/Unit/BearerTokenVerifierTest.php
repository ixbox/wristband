<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Tests\Unit;

use Ixbox\Wristband\Bearer\BearerConfig;
use Ixbox\Wristband\Bearer\BearerTokenVerifier;
use Ixbox\Wristband\Clock\FrozenClock;
use Ixbox\Wristband\Exception\ClaimInvalidException;
use Ixbox\Wristband\Exception\ConfigurationException;
use Ixbox\Wristband\Exception\ExpiredException;
use Ixbox\Wristband\Exception\KeyFetchFailedException;
use Ixbox\Wristband\Exception\SignatureInvalidException;
use Ixbox\Wristband\Exception\TokenMalformedException;
use Ixbox\Wristband\Identity;
use Ixbox\Wristband\Jwks\JwksProviderInterface;
use Ixbox\Wristband\Jwks\StaticJwksProvider;
use Ixbox\Wristband\Jwt\Base64Url;
use Ixbox\Wristband\Testing\JwtTokenFactory;
use PHPUnit\Framework\TestCase;

final class BearerTokenVerifierTest extends TestCase
{
    private const NOW = 1800000000;

    /** @var FrozenClock */
    private $clock;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock(self::NOW);
    }

    private function factory(string $alg = 'RS256'): JwtTokenFactory
    {
        return new JwtTokenFactory(JwtTokenFactory::DEFAULT_ISSUER, JwtTokenFactory::DEFAULT_AUDIENCE, $alg, $this->clock);
    }

    public function testRs256AndEs256TokensVerify(): void
    {
        foreach (['RS256', 'ES256'] as $alg) {
            $jwt = $this->factory($alg);
            $identity = $jwt->verifier()->verify($jwt->issue([
                'sub' => 'u-1',
                'email' => 'hanako@example.com',
                'preferred_username' => 'hanako',
                'groups' => ['a', 'b'],
            ]));
            self::assertSame(Identity::SOURCE_BEARER, $identity->source(), $alg);
            self::assertSame('u-1', $identity->sub());
            self::assertSame('hanako@example.com', $identity->email());
            self::assertSame('hanako', $identity->username());
            self::assertSame(['a', 'b'], $identity->groups());
            self::assertTrue($identity->emailVerified());
        }
    }

    public function testCognitoClaimsArePreferred(): void
    {
        $jwt = $this->factory();
        $identity = $jwt->verifier()->verify($jwt->issue([
            'cognito:username' => 'cog-user',
            'preferred_username' => 'pref',
            'cognito:groups' => ['g1'],
        ]));
        self::assertSame('cog-user', $identity->username());
        self::assertSame(['g1'], $identity->groups());
    }

    /**
     * @dataProvider forbiddenAlgorithms
     */
    public function testAlgorithmAllowList(string $alg): void
    {
        $jwt = $this->factory();
        $this->expectException(TokenMalformedException::class);
        $jwt->verifier()->verify($jwt->issue([], ['alg' => $alg]));
    }

    /** @return array<string, array{0: string}> */
    public static function forbiddenAlgorithms(): array
    {
        return ['none' => ['none'], 'HS256' => ['HS256'], 'RS512' => ['RS512']];
    }

    public function testHs256WithPublicKeyAsSecretIsRejected(): void
    {
        // Classic alg confusion: sign with HMAC using the public key bytes.
        $jwt = $this->factory();
        $header = Base64Url::encode((string) json_encode(['alg' => 'HS256', 'kid' => $jwt->kid()]));
        $payload = Base64Url::encode((string) json_encode(['iss' => $jwt->issuer(), 'aud' => $jwt->audience(), 'sub' => 'x', 'exp' => self::NOW + 60]));
        $sig = Base64Url::encode(hash_hmac('sha256', $header . '.' . $payload, (string) json_encode($jwt->jwks()), true));

        $this->expectException(TokenMalformedException::class);
        $jwt->verifier()->verify($header . '.' . $payload . '.' . $sig);
    }

    public function testIssuerMustMatchBeforeKeyLookup(): void
    {
        $jwt = $this->factory();
        $jwks = $this->createMock(JwksProviderInterface::class);
        $jwks->expects(self::never())->method('getKey');
        $verifier = new BearerTokenVerifier($jwt->config(), $jwks, $this->clock);

        try {
            $verifier->verify($jwt->issue(['iss' => 'https://evil.example']));
            self::fail('Expected ClaimInvalidException');
        } catch (ClaimInvalidException $e) {
            self::assertSame('issuer_mismatch', $e->reason());
        }
    }

    public function testAudience(): void
    {
        $jwt = $this->factory();
        $verifier = $jwt->verifier();

        self::assertInstanceOf(Identity::class, $verifier->verify($jwt->issue(['aud' => ['other', JwtTokenFactory::DEFAULT_AUDIENCE]])));

        try {
            $verifier->verify($jwt->issue(['aud' => 'other']));
            self::fail('Expected audience_mismatch');
        } catch (ClaimInvalidException $e) {
            self::assertSame('audience_mismatch', $e->reason());
        }
    }

    public function testCognitoAccessTokenUsesClientId(): void
    {
        $jwt = $this->factory();
        $config = $jwt->config(30, 'access');
        $verifier = new BearerTokenVerifier($config, $jwt->jwksProvider(), $this->clock);

        $access = $jwt->issue(['aud' => null, 'client_id' => JwtTokenFactory::DEFAULT_AUDIENCE, 'token_use' => 'access']);
        self::assertInstanceOf(Identity::class, $verifier->verify($access));

        $this->expectException(ClaimInvalidException::class);
        $verifier->verify($jwt->issue(['aud' => null, 'client_id' => 'other', 'token_use' => 'access']));
    }

    public function testClientIdDoesNotOverrideAWrongAud(): void
    {
        $jwt = $this->factory();
        $this->expectException(ClaimInvalidException::class);
        $jwt->verifier()->verify($jwt->issue(['aud' => 'other', 'client_id' => JwtTokenFactory::DEFAULT_AUDIENCE]));
    }

    public function testTokenUse(): void
    {
        $jwt = $this->factory();
        $verifier = new BearerTokenVerifier($jwt->config(30, 'id'), $jwt->jwksProvider(), $this->clock);
        self::assertInstanceOf(Identity::class, $verifier->verify($jwt->issue(['token_use' => 'id'])));

        try {
            $verifier->verify($jwt->issue(['token_use' => 'access']));
            self::fail('Expected token_use_mismatch');
        } catch (ClaimInvalidException $e) {
            self::assertSame('token_use_mismatch', $e->reason());
        }
    }

    public function testTimeClaims(): void
    {
        $jwt = $this->factory();
        $verifier = $jwt->verifier();

        try {
            $verifier->verify($jwt->issue(['exp' => null]));
            self::fail('exp is required');
        } catch (TokenMalformedException $e) {
            self::assertSame('exp_missing', $e->reason());
        }
        try {
            $verifier->verify($jwt->issue(['nbf' => self::NOW + 31]));
            self::fail('nbf in the future');
        } catch (ClaimInvalidException $e) {
            self::assertSame('not_yet_valid', $e->reason());
        }
        try {
            $verifier->verify($jwt->issue(['iat' => self::NOW + 31]));
            self::fail('iat in the future');
        } catch (ClaimInvalidException $e) {
            self::assertSame('issued_in_future', $e->reason());
        }
        self::assertInstanceOf(Identity::class, $verifier->verify($jwt->issue(['nbf' => self::NOW + 30, 'iat' => self::NOW + 30])));

        $this->expectException(ExpiredException::class);
        $verifier->verify($jwt->issue(['exp' => self::NOW - 31]));
    }

    public function testJwkMustMatchAlgorithm(): void
    {
        $rsa = $this->factory('RS256');
        $ec = $this->factory('ES256');
        // Serve the RSA key under the kid the ES256 token claims.
        $jwks = new StaticJwksProvider(['keys' => [array_merge($rsa->jwks()['keys'][0], ['alg' => null])]]);
        $verifier = new BearerTokenVerifier($ec->config(), $jwks, $this->clock);

        try {
            $verifier->verify($ec->issue());
            self::fail('Expected key_type_mismatch');
        } catch (SignatureInvalidException $e) {
            self::assertSame('key_type_mismatch', $e->reason());
        }
    }

    public function testWrongKeyFailsSignature(): void
    {
        $a = $this->factory();
        $b = $this->factory();
        $verifier = new BearerTokenVerifier($a->config(), $b->jwksProvider(), $this->clock);
        $this->expectException(SignatureInvalidException::class);
        $verifier->verify($a->issue());
    }

    public function testUnknownKid(): void
    {
        $jwt = $this->factory();
        $this->expectException(KeyFetchFailedException::class);
        $jwt->verifier()->verify($jwt->issue([], ['kid' => 'other']));
    }

    public function testConfigRequiresAudience(): void
    {
        $this->expectException(ConfigurationException::class);
        new BearerConfig('https://idp.example.test', []);
    }

    public function testConfigRejectsUnsupportedAlgorithms(): void
    {
        $this->expectException(ConfigurationException::class);
        new BearerConfig('https://idp.example.test', 'aud', ['HS256']);
    }
}
