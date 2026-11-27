<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Tests\Unit;

use Ixbox\Wristband\Cache\ArrayCache;
use Ixbox\Wristband\Cache\Psr16Cache;
use Ixbox\Wristband\Clock\FrozenClock;
use Ixbox\Wristband\Exception\ConfigurationException;
use Ixbox\Wristband\Exception\KeyFetchFailedException;
use Ixbox\Wristband\Http\HttpException;
use Ixbox\Wristband\Http\HttpResponse;
use Ixbox\Wristband\Jwks\HttpJwksProvider;
use Ixbox\Wristband\Key\CachedKeyProvider;
use Ixbox\Wristband\Key\HttpKeyProvider;
use Ixbox\Wristband\Key\KeyProviderInterface;
use Ixbox\Wristband\Testing\JwtTokenFactory;
use Ixbox\Wristband\Testing\KeyPair;
use Ixbox\Wristband\Tests\Support\FakeHttpClient;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface as PsrCache;

final class KeyProvidersTest extends TestCase
{
    private const KID = '0a1b2c3d-1111-2222-3333-444455556666';

    public function testHttpKeyProviderBuildsRegionalUrl(): void
    {
        $pem = KeyPair::generate('ES256')->publicPem();
        $http = (new FakeHttpClient())->on('https://public-keys.auth.elb.ap-northeast-1.amazonaws.com/' . self::KID, new HttpResponse(200, $pem));

        $provider = HttpKeyProvider::forRegion('ap-northeast-1', $http);
        self::assertSame(trim($pem), trim($provider->get(self::KID)));
    }

    public function testHttpKeyProviderWithCustomBaseUrl(): void
    {
        $pem = KeyPair::generate('ES256')->publicPem();
        $http = (new FakeHttpClient())->on('http://localhost:8080/keys/' . self::KID, new HttpResponse(200, $pem));

        self::assertStringContainsString('BEGIN PUBLIC KEY', (new HttpKeyProvider('http://localhost:8080/keys/', $http))->get(self::KID));
        self::assertStringContainsString('BEGIN PUBLIC KEY', (new HttpKeyProvider('http://localhost:8080/keys/{kid}', $http))->get(self::KID));
    }

    public function testHttpKeyProviderFailures(): void
    {
        $http = (new FakeHttpClient())
            ->on('https://k.test/500', new HttpResponse(500, 'oops'))
            ->on('https://k.test/html', new HttpResponse(200, '<html></html>'))
            ->on('https://k.test/timeout', new HttpException('timeout'));
        $provider = new HttpKeyProvider('https://k.test/{kid}', $http);

        foreach (['500' => 'key_fetch_status', 'html' => 'invalid_public_key', 'timeout' => 'key_fetch_error'] as $kid => $reason) {
            try {
                $provider->get((string) $kid);
                self::fail('Expected KeyFetchFailedException');
            } catch (KeyFetchFailedException $e) {
                self::assertSame($reason, $e->reason());
            }
        }
    }

    public function testRegionIsValidated(): void
    {
        $this->expectException(ConfigurationException::class);
        HttpKeyProvider::forRegion('evil.example.com/x');
    }

    public function testCachedKeyProviderCachesAndBacksOff(): void
    {
        $clock = new FrozenClock(1000);
        $inner = $this->createMock(KeyProviderInterface::class);
        $inner->expects(self::exactly(2))->method('get')->willReturnCallback(static function (string $kid): string {
            if ($kid === 'bad') {
                throw new KeyFetchFailedException('key_fetch_status');
            }

            return 'PEM-' . $kid;
        });
        $cache = new ArrayCache($clock);
        $provider = new CachedKeyProvider($inner, $cache, 3600, 10);

        self::assertSame('PEM-a', $provider->get('a'));
        self::assertSame('PEM-a', $provider->get('a'));
        // A second process sharing the cache does not refetch either.
        self::assertSame('PEM-a', (new CachedKeyProvider($inner, $cache))->get('a'));

        try {
            $provider->get('bad');
            self::fail('Expected failure');
        } catch (KeyFetchFailedException $e) {
            self::assertSame('key_fetch_status', $e->reason());
        }
        try {
            $provider->get('bad');
            self::fail('Expected backoff');
        } catch (KeyFetchFailedException $e) {
            self::assertSame('key_fetch_backoff', $e->reason());
        }
    }

    public function testPsr16AdapterSwallowsCacheErrors(): void
    {
        $psr = $this->createMock(PsrCache::class);
        $psr->method('get')->willThrowException(new \RuntimeException('redis down'));
        $psr->method('set')->willThrowException(new \RuntimeException('redis down'));
        $cache = new Psr16Cache($psr);

        self::assertNull($cache->get('k'));
        $cache->set('k', 'v', 10);
    }

    public function testPsr16AdapterHashesKeys(): void
    {
        $psr = $this->createMock(PsrCache::class);
        $psr->expects(self::once())->method('set')->with(self::matchesRegularExpressionCompat('/^wristband\.[0-9a-f]{64}$/'), 'v', 10);
        (new Psr16Cache($psr))->set('alb_key:alb:{weird}/key', 'v', 10);
    }

    public function testJwksProviderFetchesCachesAndRotates(): void
    {
        $clock = new FrozenClock(1000);
        $first = new JwtTokenFactory('https://idp.test', 'aud', 'RS256', $clock, 'k1');
        $second = new JwtTokenFactory('https://idp.test', 'aud', 'RS256', $clock, 'k2');
        $http = (new FakeHttpClient())->on('https://idp.test/jwks', new HttpResponse(200, (string) json_encode($first->jwks())));
        $provider = HttpJwksProvider::fromJwksUri('https://idp.test/jwks', $http, new ArrayCache($clock), 3600, 60, 2.0, $clock);

        self::assertSame('k1', $provider->getKey('k1')['kid']);
        self::assertSame('k1', $provider->getKey('k1')['kid']);
        self::assertCount(1, $http->requests);

        // Unknown kid right after a fetch: no refetch (cooldown).
        try {
            $provider->getKey('k2');
            self::fail('Expected unknown_kid');
        } catch (KeyFetchFailedException $e) {
            self::assertSame('unknown_kid', $e->reason());
        }
        self::assertCount(1, $http->requests);

        // Keys rotate; after the cooldown the unknown kid triggers one refetch.
        $http->on('https://idp.test/jwks', new HttpResponse(200, (string) json_encode(['keys' => array_merge($first->jwks()['keys'], $second->jwks()['keys'])])));
        $clock->advance(61);
        self::assertSame('k2', $provider->getKey('k2')['kid']);
        self::assertCount(2, $http->requests);
    }

    public function testJwksProviderDiscovery(): void
    {
        $jwt = new JwtTokenFactory('https://idp.test/pool', 'aud');
        $http = (new FakeHttpClient())
            ->on('https://idp.test/pool/.well-known/openid-configuration', new HttpResponse(200, (string) json_encode(['jwks_uri' => 'https://idp.test/pool/keys'])))
            ->on('https://idp.test/pool/keys', new HttpResponse(200, (string) json_encode($jwt->jwks())));

        $provider = HttpJwksProvider::fromIssuer('https://idp.test/pool/', $http);
        self::assertSame($jwt->kid(), $provider->getKey($jwt->kid())['kid']);
    }

    public function testJwksProviderBacksOffAfterInitialFailure(): void
    {
        $clock = new FrozenClock(1000);
        $http = (new FakeHttpClient())->on('https://idp.test/jwks', new HttpException('connection refused'));
        $provider = HttpJwksProvider::fromJwksUri('https://idp.test/jwks', $http, new ArrayCache($clock), 3600, 60, 2.0, $clock);

        foreach (['jwks_fetch_error', 'jwks_fetch_backoff'] as $reason) {
            try {
                $provider->getKey('k1');
                self::fail('Expected ' . $reason);
            } catch (KeyFetchFailedException $e) {
                self::assertSame($reason, $e->reason());
            }
        }
        self::assertCount(1, $http->requests);
        $clock->advance(10);
        try {
            $provider->getKey('k1');
        } catch (KeyFetchFailedException $e) {
            self::assertSame('jwks_fetch_error', $e->reason());
        }
        self::assertCount(2, $http->requests);
    }

    public function testJwksSkipsEncryptionKeys(): void
    {
        $jwt = new JwtTokenFactory();
        $jwks = $jwt->jwks();
        $jwks['keys'][0]['use'] = 'enc';
        $http = (new FakeHttpClient())->on('https://idp.test/jwks', new HttpResponse(200, (string) json_encode($jwks)));

        $this->expectException(KeyFetchFailedException::class);
        HttpJwksProvider::fromJwksUri('https://idp.test/jwks', $http)->getKey($jwt->kid());
    }

    /**
     * assertMatchesRegularExpression does not exist in PHPUnit 8.
     *
     * @return \PHPUnit\Framework\Constraint\Constraint
     */
    private static function matchesRegularExpressionCompat(string $pattern)
    {
        return self::callback(static function ($value) use ($pattern): bool {
            return is_string($value) && preg_match($pattern, $value) === 1;
        });
    }
}
