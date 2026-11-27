<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Tests\Unit;

use Ixbox\EdgeIdentity\Clock\FrozenClock;
use Ixbox\EdgeIdentity\Exception\ConfigurationException;
use Ixbox\EdgeIdentity\Exception\SignatureInvalidException;
use Ixbox\EdgeIdentity\Exception\TokenMalformedException;
use Ixbox\EdgeIdentity\Exception\TokenMissingException;
use Ixbox\EdgeIdentity\Exception\UntrustedRequestException;
use Ixbox\EdgeIdentity\Identity;
use Ixbox\EdgeIdentity\Request\ProxyRequest;
use Ixbox\EdgeIdentity\Source\AlbOidcDataSource;
use Ixbox\EdgeIdentity\Source\BearerJwtSource;
use Ixbox\EdgeIdentity\Source\ChainSource;
use Ixbox\EdgeIdentity\Source\TrustedHeadersConfig;
use Ixbox\EdgeIdentity\Source\TrustedHeadersSource;
use Ixbox\EdgeIdentity\Testing\AlbTokenFactory;
use Ixbox\EdgeIdentity\Testing\JwtTokenFactory;
use PHPUnit\Framework\TestCase;

final class SourcesTest extends TestCase
{
    private const SECRET = 'a-very-long-shared-secret';

    /** @var FrozenClock */
    private $clock;
    /** @var AlbTokenFactory */
    private $alb;
    /** @var JwtTokenFactory */
    private $jwt;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock(1800000000);
        $this->alb = new AlbTokenFactory(AlbTokenFactory::DEFAULT_SIGNER, AlbTokenFactory::DEFAULT_CLIENT, AlbTokenFactory::DEFAULT_ISSUER, $this->clock);
        $this->jwt = new JwtTokenFactory(JwtTokenFactory::DEFAULT_ISSUER, JwtTokenFactory::DEFAULT_AUDIENCE, 'RS256', $this->clock);
    }

    public function testAlbSourceReadsHeaderCaseInsensitively(): void
    {
        $source = new AlbOidcDataSource($this->alb->verifier());
        $request = ProxyRequest::fromArray(['X-Amzn-Oidc-Data' => $this->alb->issue(['sub' => 's1'])]);
        self::assertSame('s1', $source->authenticate($request)->sub());
    }

    public function testAlbSourceRejectsRepeatedHeader(): void
    {
        $source = new AlbOidcDataSource($this->alb->verifier());
        $token = $this->alb->issue();
        $this->expectException(TokenMalformedException::class);
        $source->authenticate(ProxyRequest::fromArray(['x-amzn-oidc-data' => [$token, $token]]));
    }

    public function testAlbSourceRejectsOverlongHeader(): void
    {
        $source = new AlbOidcDataSource($this->alb->verifier());
        $this->expectException(TokenMalformedException::class);
        $source->authenticate(ProxyRequest::fromArray(['x-amzn-oidc-data' => str_repeat('a', 70000)]));
    }

    public function testAlbSourceIgnoresUnsignedHeaders(): void
    {
        $source = new AlbOidcDataSource($this->alb->verifier());
        $this->expectException(TokenMissingException::class);
        $source->authenticate(ProxyRequest::fromArray([
            'x-amzn-oidc-identity' => 'admin',
            'x-amzn-oidc-accesstoken' => 'whatever',
        ]));
    }

    public function testBearerSource(): void
    {
        $source = new BearerJwtSource($this->jwt->verifier());
        $identity = $source->authenticate(ProxyRequest::fromArray(['Authorization' => 'Bearer ' . $this->jwt->issue(['sub' => 'b1'])]));
        self::assertSame('b1', $identity->sub());
        $identity = $source->authenticate(ProxyRequest::fromArray(['Authorization' => 'bearer ' . $this->jwt->issue(['sub' => 'b2'])]));
        self::assertSame('b2', $identity->sub());
    }

    public function testBearerSourceTreatsOtherSchemesAsMissing(): void
    {
        $source = new BearerJwtSource($this->jwt->verifier());
        $this->expectException(TokenMissingException::class);
        $source->authenticate(ProxyRequest::fromArray(['Authorization' => 'Basic dXNlcjpwYXNz']));
    }

    public function testBearerSourceWithBareTokenHeader(): void
    {
        $source = new BearerJwtSource($this->jwt->verifier(), 'X-Forwarded-Access-Token', null);
        $identity = $source->authenticate(ProxyRequest::fromArray(['X-Forwarded-Access-Token' => $this->jwt->issue(['sub' => 'b3'])]));
        self::assertSame('b3', $identity->sub());
    }

    public function testTrustedHeadersRequireSecretOrProxies(): void
    {
        $this->expectException(ConfigurationException::class);
        new TrustedHeadersConfig([]);
    }

    public function testTrustedHeadersRejectShortSecret(): void
    {
        $this->expectException(ConfigurationException::class);
        new TrustedHeadersConfig(['shared_secret_header' => 'X-Edge-Secret', 'shared_secret' => 'short']);
    }

    public function testTrustedHeadersWithSharedSecret(): void
    {
        $source = new TrustedHeadersSource(new TrustedHeadersConfig([
            'shared_secret_header' => 'X-Edge-Secret',
            'shared_secret' => self::SECRET,
        ]));
        $identity = $source->authenticate(ProxyRequest::fromArray([
            'X-Edge-Secret' => self::SECRET,
            'X-Forwarded-User' => 'u-9',
            'X-Forwarded-Email' => 'jiro@example.com',
            'X-Forwarded-Preferred-Username' => 'jiro',
            'X-Forwarded-Groups' => 'admin, dev',
        ]));

        self::assertSame(Identity::SOURCE_TRUSTED_HEADERS, $identity->source());
        self::assertSame('u-9', $identity->sub());
        self::assertSame('jiro@example.com', $identity->email());
        self::assertNull($identity->emailVerified());
        self::assertSame('jiro', $identity->username());
        self::assertSame(['admin', 'dev'], $identity->groups());
    }

    public function testTrustedHeadersWithoutSecretAreRejected(): void
    {
        $source = new TrustedHeadersSource(new TrustedHeadersConfig(['shared_secret_header' => 'X-Edge-Secret', 'shared_secret' => self::SECRET]));
        foreach ([[], ['X-Edge-Secret' => 'wrong-secret-value-123'], ['X-Edge-Secret' => [self::SECRET, self::SECRET]]] as $extra) {
            try {
                $source->authenticate(ProxyRequest::fromArray($extra + ['X-Forwarded-User' => 'u']));
                self::fail('Expected UntrustedRequestException');
            } catch (UntrustedRequestException $e) {
                self::assertSame('shared_secret_mismatch', $e->reason());
            }
        }
    }

    public function testTrustedHeadersWithProxyAllowList(): void
    {
        $source = new TrustedHeadersSource(new TrustedHeadersConfig(['preset' => 'x-auth-request', 'trusted_proxies' => '10.0.0.0/8, fd00::/8']));
        $headers = ['X-Auth-Request-User' => 'u', 'X-Auth-Request-Email' => 'u@example.com'];

        self::assertSame('u@example.com', $source->authenticate(ProxyRequest::fromArray($headers, '10.1.2.3'))->email());
        self::assertSame('u', $source->authenticate(ProxyRequest::fromArray($headers, 'fd12::1'))->sub());

        foreach (['192.168.1.1', null] as $remote) {
            try {
                $source->authenticate(ProxyRequest::fromArray($headers, $remote));
                self::fail('Expected UntrustedRequestException');
            } catch (UntrustedRequestException $e) {
                self::assertSame('untrusted_peer', $e->reason());
            }
        }
    }

    public function testTrustedHeadersMissingUserIsMissing(): void
    {
        $source = new TrustedHeadersSource(new TrustedHeadersConfig(['trusted_proxies' => ['127.0.0.1']]));
        $this->expectException(TokenMissingException::class);
        $source->authenticate(ProxyRequest::fromArray(['X-Forwarded-Email' => 'x@example.com'], '127.0.0.1'));
    }

    public function testChainFallsThroughOnlyOnMissing(): void
    {
        $chain = new ChainSource([
            new AlbOidcDataSource($this->alb->verifier()),
            new BearerJwtSource($this->jwt->verifier()),
        ]);

        self::assertSame(Identity::SOURCE_ALB, $chain->authenticate(ProxyRequest::fromArray(['x-amzn-oidc-data' => $this->alb->issue()]))->source());
        self::assertSame(Identity::SOURCE_BEARER, $chain->authenticate(ProxyRequest::fromArray(['authorization' => 'Bearer ' . $this->jwt->issue()]))->source());

        try {
            $chain->authenticate(ProxyRequest::fromArray([]));
            self::fail('Expected TokenMissingException');
        } catch (TokenMissingException $e) {
            self::assertSame('no_credentials', $e->reason());
        }

        // A forged ALB token must not fall through to the bearer source.
        $other = new AlbTokenFactory($this->alb->signer(), AlbTokenFactory::DEFAULT_CLIENT, AlbTokenFactory::DEFAULT_ISSUER, $this->clock, $this->alb->kid());
        $this->expectException(SignatureInvalidException::class);
        $chain->authenticate(ProxyRequest::fromArray([
            'x-amzn-oidc-data' => $other->issue(),
            'authorization' => 'Bearer ' . $this->jwt->issue(),
        ]));
    }
}
