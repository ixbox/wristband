<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Tests\Unit;

use Ixbox\Wristband\Alb\AlbConfig;
use Ixbox\Wristband\Alb\AlbTokenVerifier;
use Ixbox\Wristband\Clock\FrozenClock;
use Ixbox\Wristband\Exception\AuthenticationException;
use Ixbox\Wristband\Exception\ClaimInvalidException;
use Ixbox\Wristband\Exception\ConfigurationException;
use Ixbox\Wristband\Exception\ExpiredException;
use Ixbox\Wristband\Exception\KeyFetchFailedException;
use Ixbox\Wristband\Exception\SignatureInvalidException;
use Ixbox\Wristband\Exception\SignerMismatchException;
use Ixbox\Wristband\Exception\TokenMalformedException;
use Ixbox\Wristband\Exception\TokenMissingException;
use Ixbox\Wristband\Identity;
use Ixbox\Wristband\Jwt\Base64Url;
use Ixbox\Wristband\Key\KeyProviderInterface;
use Ixbox\Wristband\Key\StaticKeyProvider;
use Ixbox\Wristband\Testing\AlbTokenFactory;
use PHPUnit\Framework\TestCase;

final class AlbTokenVerifierTest extends TestCase
{
    private const NOW = 1800000000;

    /** @var FrozenClock */
    private $clock;
    /** @var AlbTokenFactory */
    private $alb;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock(self::NOW);
        $this->alb = new AlbTokenFactory(AlbTokenFactory::DEFAULT_SIGNER, AlbTokenFactory::DEFAULT_CLIENT, AlbTokenFactory::DEFAULT_ISSUER, $this->clock);
    }

    public function testValidTokenYieldsIdentity(): void
    {
        $token = $this->alb->issue([
            'sub' => 'abc-123',
            'email' => 'taro@example.com',
            'username' => 'taro',
            'cognito:groups' => ['admin', 'dev'],
        ]);

        $identity = $this->alb->verifier()->verify($token);

        self::assertSame(Identity::SOURCE_ALB, $identity->source());
        self::assertSame('abc-123', $identity->sub());
        self::assertSame('taro@example.com', $identity->email());
        self::assertTrue($identity->emailVerified());
        self::assertSame('taro', $identity->username());
        self::assertSame(['admin', 'dev'], $identity->groups());
        self::assertSame($this->alb->signer(), $identity->header()['signer']);
        self::assertSame($this->alb->kid(), $identity->header()['kid']);
        self::assertSame(AlbTokenFactory::DEFAULT_ISSUER, $identity->issuer());
        self::assertSame(self::NOW + 120, $identity->expiresAt());
    }

    public function testTokenIsPaddedLikeAlb(): void
    {
        // The factory must reproduce the ALB quirk; make sure at least one segment carries "=".
        $found = false;
        for ($i = 0; $i < 10 && !$found; $i++) {
            $found = str_contains($this->alb->issue(['email' => str_repeat('x', $i) . '@example.com']), '=');
        }
        self::assertTrue($found);
    }

    public function testUnpaddedTokenIsAcceptedToo(): void
    {
        $parts = explode('.', $this->alb->issue());
        $unpaddedSignature = rtrim($parts[2], '=');
        // Only the signature can be re-encoded freely; the first two segments are signed as sent.
        $token = $parts[0] . '.' . $parts[1] . '.' . $unpaddedSignature;

        self::assertInstanceOf(Identity::class, $this->alb->verifier()->verify($token));
    }

    public function testEmptyTokenIsMissing(): void
    {
        $this->expectException(TokenMissingException::class);
        $this->alb->verifier()->verify('');
    }

    /**
     * @dataProvider malformedTokens
     */
    public function testMalformedTokens(string $token, string $reason): void
    {
        try {
            $this->alb->verifier()->verify($token);
            self::fail('Expected TokenMalformedException');
        } catch (TokenMalformedException $e) {
            self::assertSame($reason, $e->reason());
        }
    }

    /** @return array<string, array{0: string, 1: string}> */
    public static function malformedTokens(): array
    {
        $json = static function (string $data): string {
            return Base64Url::encode($data);
        };

        return [
            'two segments' => ['a.b', 'invalid_format'],
            'four segments' => ['a.b.c.d', 'invalid_format'],
            'bad base64' => ['$$$.e30.c2ln', 'invalid_header_encoding'],
            'header not json' => [$json('nope') . '.' . $json('{}') . '.c2ln', 'invalid_header_json'],
            'header json array' => [$json('[1]') . '.' . $json('{}') . '.c2ln', 'invalid_header_json'],
            'payload not json' => [$json('{}') . '.' . $json('nope') . '.c2ln', 'invalid_payload_json'],
            // PHP-FPM joins a repeated header as "a, b".
            'joined duplicate header' => [$json('{}') . '.' . $json('{}') . '.c2ln, ' . $json('{}') . '.' . $json('{}') . '.c2ln', 'invalid_format'],
            'comma in signature' => [$json('{}') . '.' . $json('{}') . '.c2ln,e30', 'invalid_signature_encoding'],
            'too long' => [str_repeat('a', 20000), 'too_long'],
        ];
    }

    /**
     * @dataProvider forbiddenAlgorithms
     */
    public function testOnlyEs256IsAllowed(?string $alg): void
    {
        $token = $this->alb->issue([], ['alg' => $alg]);
        try {
            $this->alb->verifier()->verify($token);
            self::fail('Expected TokenMalformedException');
        } catch (TokenMalformedException $e) {
            self::assertSame('alg_not_allowed', $e->reason());
        }
    }

    /** @return array<string, array{0: string|null}> */
    public static function forbiddenAlgorithms(): array
    {
        return ['none' => ['none'], 'HS256' => ['HS256'], 'RS256' => ['RS256'], 'ES384' => ['ES384'], 'lowercase' => ['es256'], 'missing' => [null]];
    }

    public function testNoneAlgorithmWithEmptySignatureIsRejected(): void
    {
        $token = Base64Url::encode('{"alg":"none","signer":"' . $this->alb->signer() . '","kid":"' . $this->alb->kid() . '"}')
            . '.' . Base64Url::encode('{"sub":"x"}') . '.';
        $this->expectException(TokenMalformedException::class);
        $this->alb->verifier()->verify($token);
    }

    public function testSignerMustMatch(): void
    {
        $other = new AlbTokenFactory('arn:aws:elasticloadbalancing:ap-northeast-1:999999999999:loadbalancer/app/evil/1', AlbTokenFactory::DEFAULT_CLIENT, AlbTokenFactory::DEFAULT_ISSUER, $this->clock);
        $this->expectException(SignerMismatchException::class);
        $this->alb->verifier()->verify($other->issue());
    }

    public function testSignerIsCheckedBeforeAnyKeyFetch(): void
    {
        $keys = $this->createMock(KeyProviderInterface::class);
        $keys->expects(self::never())->method('get');
        $verifier = new AlbTokenVerifier($this->alb->config(), $keys, $this->clock);

        $this->expectException(SignerMismatchException::class);
        $verifier->verify($this->alb->issue([], ['signer' => 'arn:aws:elasticloadbalancing:ap-northeast-1:1:loadbalancer/app/x/y']));
    }

    public function testSeveralSignersCanBeAllowed(): void
    {
        $second = new AlbTokenFactory('arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:loadbalancer/app/second/1', AlbTokenFactory::DEFAULT_CLIENT, AlbTokenFactory::DEFAULT_ISSUER, $this->clock);
        $config = new AlbConfig([$this->alb->signer(), $second->signer()], null, AlbTokenFactory::DEFAULT_CLIENT);
        $keys = new StaticKeyProvider([$this->alb->kid() => $this->alb->publicKeyPem(), $second->kid() => $second->publicKeyPem()]);
        $verifier = new AlbTokenVerifier($config, $keys, $this->clock);

        self::assertSame('a', $verifier->verify($this->alb->issue(['sub' => 'a']))->sub());
        self::assertSame('b', $verifier->verify($second->issue(['sub' => 'b']))->sub());
    }

    /**
     * @dataProvider badKids
     */
    public function testKidMustBeUuid(string $kid): void
    {
        $keys = $this->createMock(KeyProviderInterface::class);
        $keys->expects(self::never())->method('get');
        $verifier = new AlbTokenVerifier($this->alb->config(), $keys, $this->clock);

        try {
            $verifier->verify($this->alb->issue([], ['kid' => $kid]));
            self::fail('Expected TokenMalformedException');
        } catch (TokenMalformedException $e) {
            self::assertSame('invalid_kid', $e->reason());
        }
    }

    /** @return array<string, array{0: string}> */
    public static function badKids(): array
    {
        return [
            'path traversal' => ['../../latest/meta-data'],
            'url' => ['http://169.254.169.254/'],
            'uuid with suffix' => ['12345678-1234-1234-1234-1234567890ab/x'],
            'empty' => [''],
        ];
    }

    public function testTamperedPayloadFailsSignature(): void
    {
        $parts = explode('.', $this->alb->issue(['email' => 'user@example.com']));
        $payload = json_decode((string) Base64Url::decode($parts[1]), true);
        $payload['email'] = 'admin@example.com';
        $parts[1] = Base64Url::encode((string) json_encode($payload), true);

        $this->expectException(SignatureInvalidException::class);
        $this->alb->verifier()->verify(implode('.', $parts));
    }

    public function testSignatureFromAnotherKeyFails(): void
    {
        $impostor = new AlbTokenFactory($this->alb->signer(), AlbTokenFactory::DEFAULT_CLIENT, AlbTokenFactory::DEFAULT_ISSUER, $this->clock, $this->alb->kid());
        $this->expectException(SignatureInvalidException::class);
        $this->alb->verifier()->verify($impostor->issue());
    }

    public function testUnknownKidIsKeyFetchFailure(): void
    {
        $verifier = new AlbTokenVerifier($this->alb->config(), new StaticKeyProvider([]), $this->clock);
        $this->expectException(KeyFetchFailedException::class);
        $verifier->verify($this->alb->issue());
    }

    public function testClientIsCheckedWhenConfigured(): void
    {
        $token = $this->alb->issue([], ['client' => 'someone-else']);
        try {
            $this->alb->verifier()->verify($token);
            self::fail('Expected ClaimInvalidException');
        } catch (ClaimInvalidException $e) {
            self::assertSame('client_mismatch', $e->reason());
        }

        $unchecked = new AlbTokenVerifier(new AlbConfig($this->alb->signer()), $this->alb->keyProvider(), $this->clock);
        self::assertInstanceOf(Identity::class, $unchecked->verify($token));
    }

    public function testIssuerIsCheckedWhenConfigured(): void
    {
        $config = $this->alb->config()->withIssuer('https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_OTHER');
        $verifier = new AlbTokenVerifier($config, $this->alb->keyProvider(), $this->clock);
        $this->expectException(ClaimInvalidException::class);
        $verifier->verify($this->alb->issue());
    }

    public function testExpiryUsesLeeway(): void
    {
        $token = $this->alb->issue([], [], 60);
        $verifier = $this->alb->verifier();

        $this->clock->set(self::NOW + 60 + 30);
        self::assertInstanceOf(Identity::class, $verifier->verify($token));

        $this->clock->set(self::NOW + 60 + 31);
        $this->expectException(ExpiredException::class);
        $verifier->verify($token);
    }

    public function testHeaderExpIsRequired(): void
    {
        $this->expectException(TokenMalformedException::class);
        $this->alb->verifier()->verify($this->alb->issue([], ['exp' => null]));
    }

    public function testPayloadExpIsCheckedToo(): void
    {
        $this->expectException(ExpiredException::class);
        $this->alb->verifier()->verify($this->alb->issue(['exp' => self::NOW - 3600]));
    }

    public function testPayloadWithoutExpIsAccepted(): void
    {
        self::assertInstanceOf(Identity::class, $this->alb->verifier()->verify($this->alb->issue(['exp' => null])));
    }

    public function testSubjectIsRequired(): void
    {
        $this->expectException(TokenMalformedException::class);
        $this->alb->verifier()->verify($this->alb->issue(['sub' => '']));
    }

    public function testCritHeaderIsRejected(): void
    {
        $this->expectException(TokenMalformedException::class);
        $this->alb->verifier()->verify($this->alb->issue([], ['crit' => ['b64']]));
    }

    public function testExceptionsShareABaseClass(): void
    {
        try {
            $this->alb->verifier()->verify('x.y.z');
        } catch (AuthenticationException $e) {
            self::assertNotSame('', $e->reason());

            return;
        }
        self::fail('Expected an AuthenticationException');
    }

    public function testConfigDerivesRegionFromArn(): void
    {
        $config = new AlbConfig('arn:aws:elasticloadbalancing:us-west-2:1:loadbalancer/app/a/b');
        self::assertSame('us-west-2', $config->region());
    }

    public function testConfigRejectsBadValues(): void
    {
        foreach ([[[]], [''], ['arn:x', 'ap-northeast-1/../x'], ['not-an-arn']] as $args) {
            try {
                new AlbConfig(...$args);
                self::fail('Expected ConfigurationException for ' . json_encode($args));
            } catch (ConfigurationException $e) {
                self::assertNotSame('', $e->getMessage());
            }
        }
    }
}
