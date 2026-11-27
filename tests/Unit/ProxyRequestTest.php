<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Tests\Unit;

use Ixbox\EdgeIdentity\Exception\TokenMissingException;
use Ixbox\EdgeIdentity\Request\ProxyRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class ProxyRequestTest extends TestCase
{
    public function testFromGlobals(): void
    {
        $request = ProxyRequest::fromGlobals([
            'HTTP_X_AMZN_OIDC_DATA' => 'token',
            'REDIRECT_HTTP_AUTHORIZATION' => 'Bearer t',
            'REMOTE_ADDR' => '10.0.0.5',
            'SCRIPT_NAME' => '/index.php',
        ]);
        self::assertSame('token', $request->singleHeader('x-amzn-oidc-data'));
        self::assertSame('Bearer t', $request->singleHeader('Authorization'));
        self::assertSame('10.0.0.5', $request->remoteAddress());
    }

    public function testFromHttpFoundationShape(): void
    {
        // Mimics Symfony's HeaderBag / ServerBag without requiring symfony/http-foundation.
        $request = new \stdClass();
        $request->headers = new class () {
            /** @return array<string, list<string>> */
            public function all(): array
            {
                return ['x-amzn-oidc-data' => ['token']];
            }
        };
        $request->server = new class () {
            /** @return mixed */
            public function get(string $key)
            {
                return $key === 'REMOTE_ADDR' ? '10.0.0.7' : null;
            }
        };

        $proxy = ProxyRequest::fromHttpFoundation($request);
        self::assertSame('token', $proxy->singleHeader('X-Amzn-Oidc-Data'));
        self::assertSame('10.0.0.7', $proxy->remoteAddress());
    }

    public function testFromPsr7(): void
    {
        $psr = $this->createMock(ServerRequestInterface::class);
        $psr->method('getHeaders')->willReturn(['X-Amzn-Oidc-Data' => ['token']]);
        $psr->method('getServerParams')->willReturn(['REMOTE_ADDR' => '10.0.0.8']);

        $proxy = ProxyRequest::fromPsr7($psr);
        self::assertSame('token', $proxy->singleHeader('x-amzn-oidc-data'));
        self::assertSame('10.0.0.8', $proxy->remoteAddress());
    }

    public function testEmptyHeaderCountsAsMissing(): void
    {
        $this->expectException(TokenMissingException::class);
        ProxyRequest::fromArray(['x-amzn-oidc-data' => '  '])->singleHeader('x-amzn-oidc-data');
    }
}
