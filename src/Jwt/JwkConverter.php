<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Jwt;

use Ixbox\Wristband\Exception\KeyFetchFailedException;

/**
 * Turns an RSA or P-256 EC JWK into a PEM SubjectPublicKeyInfo.
 *
 * @internal
 */
final class JwkConverter
{
    private const OID_RSA_ENCRYPTION = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
    private const OID_EC_PUBLIC_KEY = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
    private const OID_PRIME256V1 = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

    /**
     * @param array<string, mixed> $jwk
     * @throws KeyFetchFailedException
     */
    public static function toPem(array $jwk): string
    {
        $kty = isset($jwk['kty']) ? $jwk['kty'] : null;
        if ($kty === 'RSA') {
            $n = self::member($jwk, 'n');
            $e = self::member($jwk, 'e');
            $der = Der::sequence(
                Der::sequence(self::OID_RSA_ENCRYPTION, "\x05\x00"),
                Der::bitString(Der::sequence(Der::integer($n), Der::integer($e)))
            );
        } elseif ($kty === 'EC') {
            if ((isset($jwk['crv']) ? $jwk['crv'] : null) !== 'P-256') {
                throw new KeyFetchFailedException('unsupported_jwk', 'Only the P-256 curve is supported.');
            }
            $x = self::member($jwk, 'x');
            $y = self::member($jwk, 'y');
            if (strlen($x) !== 32 || strlen($y) !== 32) {
                throw new KeyFetchFailedException('invalid_jwk', 'P-256 coordinates must be 32 bytes.');
            }
            $der = Der::sequence(
                Der::sequence(self::OID_EC_PUBLIC_KEY, self::OID_PRIME256V1),
                Der::bitString("\x04" . $x . $y)
            );
        } else {
            throw new KeyFetchFailedException('unsupported_jwk', 'Only RSA and EC keys are supported.');
        }

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /** @param array<string, mixed> $jwk */
    private static function member(array $jwk, string $name): string
    {
        $value = isset($jwk[$name]) && is_string($jwk[$name]) ? Base64Url::decode($jwk[$name]) : null;
        if ($value === null) {
            throw new KeyFetchFailedException('invalid_jwk', 'The JWK member "' . $name . '" is missing or invalid.');
        }

        return $value;
    }
}
