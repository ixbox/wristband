<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Tests\Unit;

use Ixbox\EdgeIdentity\ClaimMap;
use Ixbox\EdgeIdentity\Exception\ConfigurationException;
use Ixbox\EdgeIdentity\Identity;
use Ixbox\EdgeIdentity\Logout\AlbLogout;
use Ixbox\EdgeIdentity\Logout\Oauth2ProxyLogout;
use Ixbox\EdgeIdentity\Net\IpMatcher;
use PHPUnit\Framework\TestCase;

final class MiscTest extends TestCase
{
    public function testAlbLogoutCookies(): void
    {
        self::assertSame(
            ['AWSELBAuthSessionCookie', 'AWSELBAuthSessionCookie-0', 'AWSELBAuthSessionCookie-1', 'AWSELBAuthSessionCookie-2', 'AWSELBAuthSessionCookie-3'],
            AlbLogout::cookiesToExpire()
        );
        self::assertSame('Custom-3', AlbLogout::cookiesToExpire('Custom')[4]);
    }

    public function testCognitoLogoutUrl(): void
    {
        self::assertSame(
            'https://auth.example.com/logout?client_id=abc&logout_uri=https%3A%2F%2Fcp.example.com%2Flogged-out',
            AlbLogout::cognitoLogoutUrl('auth.example.com', 'abc', 'https://cp.example.com/logged-out')
        );
        self::assertSame(
            'http://localhost:9229/logout?client_id=abc&logout_uri=http%3A%2F%2Flocalhost%2F',
            AlbLogout::cognitoLogoutUrl('http://localhost:9229/', 'abc', 'http://localhost/')
        );
    }

    public function testOauth2ProxySignOutUrl(): void
    {
        self::assertSame('/oauth2/sign_out', Oauth2ProxyLogout::signOutUrl());
        self::assertSame('/oauth2/sign_out?rd=https%3A%2F%2Fidp%2Flogout%3Fa%3D1', Oauth2ProxyLogout::signOutUrl('https://idp/logout?a=1'));
    }

    public function testIpMatcher(): void
    {
        $matcher = new IpMatcher(['10.0.0.0/8', '192.168.1.10', '172.16.0.0/12', '2001:db8::/32']);
        self::assertTrue($matcher->matches('10.255.0.1'));
        self::assertTrue($matcher->matches('192.168.1.10'));
        self::assertFalse($matcher->matches('192.168.1.11'));
        self::assertTrue($matcher->matches('172.31.255.255'));
        self::assertFalse($matcher->matches('172.32.0.0'));
        self::assertTrue($matcher->matches('2001:db8:1::1'));
        self::assertFalse($matcher->matches('2001:db9::1'));
        self::assertFalse($matcher->matches('not-an-ip'));
        self::assertTrue((new IpMatcher(['0.0.0.0/0']))->matches('8.8.8.8'));
    }

    public function testIpMatcherRejectsBadRanges(): void
    {
        $this->expectException(ConfigurationException::class);
        new IpMatcher(['10.0.0.0/33']);
    }

    public function testIdentityFromClaimsWithCustomMap(): void
    {
        $identity = Identity::fromClaims('bearer', [
            'oid' => 'object-id',
            'upn' => 'user@corp.example',
            'name' => 'User',
            'roles' => 'a,b',
            'email_verified' => 'false',
        ], [], new ClaimMap('oid', 'upn', ['name'], ['roles']));

        self::assertSame('object-id', $identity->sub());
        self::assertSame('user@corp.example', $identity->email());
        self::assertFalse($identity->emailVerified());
        self::assertSame('User', $identity->username());
        self::assertSame(['a', 'b'], $identity->groups());
        self::assertSame('User', $identity->claim('name'));
        self::assertSame('x', $identity->claim('missing', 'x'));
        self::assertSame('object-id', $identity->toArray()['sub']);
    }
}
