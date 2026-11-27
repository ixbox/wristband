<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Logout;

/**
 * Values needed to log out behind an ALB. Framework independent: expire the
 * returned cookies, then redirect to the IdP logout URL (which must point
 * back to a page outside ALB authentication, e.g. /logged-out).
 */
final class AlbLogout
{
    public const DEFAULT_COOKIE = 'AWSELBAuthSessionCookie';

    /**
     * ALB splits the session cookie into -0 .. -3 when it exceeds 4 KB.
     *
     * @return list<string>
     */
    public static function cookiesToExpire(string $cookieName = self::DEFAULT_COOKIE): array
    {
        return [$cookieName, $cookieName . '-0', $cookieName . '-1', $cookieName . '-2', $cookieName . '-3'];
    }

    /**
     * Cognito managed login logout endpoint.
     *
     * @param string $domain e.g. "auth.example.com" or "xxx.auth.ap-northeast-1.amazoncognito.com" (scheme optional)
     */
    public static function cognitoLogoutUrl(string $domain, string $clientId, string $logoutUri): string
    {
        $domain = rtrim($domain, '/');
        if (preg_match('#^https?://#i', $domain) !== 1) {
            $domain = 'https://' . $domain;
        }

        return $domain . '/logout?' . http_build_query(['client_id' => $clientId, 'logout_uri' => $logoutUri], '', '&', PHP_QUERY_RFC3986);
    }
}
