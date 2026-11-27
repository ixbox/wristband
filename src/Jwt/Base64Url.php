<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Jwt;

/**
 * base64url with optional "=" padding.
 *
 * ALB pads its segments; most OIDC providers do not. Both are accepted on
 * decode. The standard alphabet ("+", "/") is accepted too: the signature
 * covers the raw segments, so accepting another spelling cannot change what
 * a valid token says.
 */
final class Base64Url
{
    public static function encode(string $data, bool $padding = false): string
    {
        $encoded = strtr(base64_encode($data), '+/', '-_');

        return $padding ? $encoded : rtrim($encoded, '=');
    }

    /** Returns null when the input is not valid base64url. */
    public static function decode(string $data): ?string
    {
        $data = rtrim($data, '=');
        if ($data === '' || strlen($data) % 4 === 1 || preg_match('/^[A-Za-z0-9_\-+\/]+$/', $data) !== 1) {
            return null;
        }
        $data = strtr($data, '-_', '+/');
        $remainder = strlen($data) % 4;
        if ($remainder !== 0) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode($data, true);

        return $decoded === false ? null : $decoded;
    }
}
