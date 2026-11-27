<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Jwks;

/**
 * @internal
 */
final class JwksDocument
{
    /**
     * Indexes the signature keys of a JWKS document by kid. Keys without a kid
     * or marked for encryption are skipped.
     *
     * @param array<string, mixed> $jwks
     * @return array<string, array<string, mixed>>
     */
    public static function index(array $jwks): array
    {
        $out = [];
        $keys = isset($jwks['keys']) && is_array($jwks['keys']) ? $jwks['keys'] : [];
        foreach ($keys as $jwk) {
            if (!is_array($jwk) || !isset($jwk['kid']) || !is_string($jwk['kid']) || $jwk['kid'] === '') {
                continue;
            }
            if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
                continue;
            }
            $out[$jwk['kid']] = $jwk;
        }

        return $out;
    }
}
