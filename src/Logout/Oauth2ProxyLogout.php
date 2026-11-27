<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Logout;

/**
 * oauth2-proxy clears its own cookie at /oauth2/sign_out and then redirects
 * to rd (which may be the IdP logout URL; allow it with --whitelist-domain).
 */
final class Oauth2ProxyLogout
{
    public static function signOutUrl(?string $redirectTo = null, string $signOutPath = '/oauth2/sign_out'): string
    {
        if ($redirectTo === null || $redirectTo === '') {
            return $signOutPath;
        }

        return $signOutPath . (str_contains($signOutPath, '?') ? '&' : '?') . 'rd=' . rawurlencode($redirectTo);
    }
}
