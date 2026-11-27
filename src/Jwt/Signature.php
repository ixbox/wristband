<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Jwt;

use Ixbox\EdgeIdentity\Exception\KeyFetchFailedException;

/**
 * ES256 and RS256 verification with ext-openssl.
 *
 * @internal
 */
final class Signature
{
    public const ES256 = 'ES256';
    public const RS256 = 'RS256';

    /**
     * @throws KeyFetchFailedException when the key is unusable for the algorithm
     */
    public static function verify(string $alg, string $signingInput, string $signature, string $publicKeyPem): bool
    {
        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false) {
            self::clearOpensslErrors();
            throw new KeyFetchFailedException('invalid_public_key', 'The public key could not be parsed.');
        }
        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            self::clearOpensslErrors();
            throw new KeyFetchFailedException('invalid_public_key', 'The public key could not be inspected.');
        }

        if ($alg === self::ES256) {
            if ($details['type'] !== OPENSSL_KEYTYPE_EC || ($details['ec']['curve_name'] ?? null) !== 'prime256v1') {
                throw new KeyFetchFailedException('key_type_mismatch', 'ES256 requires a P-256 public key.');
            }
            // JWS carries ECDSA signatures as R || S (32 bytes each); OpenSSL wants DER.
            if (strlen($signature) !== 64) {
                return false;
            }
            $signature = self::rawToDer($signature);
        } elseif ($alg === self::RS256) {
            if ($details['type'] !== OPENSSL_KEYTYPE_RSA || $details['bits'] < 2048) {
                throw new KeyFetchFailedException('key_type_mismatch', 'RS256 requires an RSA public key of at least 2048 bits.');
            }
        } else {
            return false;
        }

        $result = openssl_verify($signingInput, $signature, $key, OPENSSL_ALGO_SHA256);
        self::clearOpensslErrors();

        return $result === 1;
    }

    /** R || S (64 bytes) to a DER ECDSA-Sig-Value. */
    public static function rawToDer(string $raw): string
    {
        $half = intdiv(strlen($raw), 2);

        return Der::sequence(Der::integer(substr($raw, 0, $half)), Der::integer(substr($raw, $half)));
    }

    /** A DER ECDSA-Sig-Value to R || S, each left-padded to $partLength bytes. */
    public static function derToRaw(string $der, int $partLength = 32): string
    {
        $parts = Der::readEcdsaSignature($der);
        if ($parts === null || strlen($parts[0]) > $partLength || strlen($parts[1]) > $partLength) {
            throw new \InvalidArgumentException('Not a DER ECDSA signature for this curve.');
        }

        return str_pad($parts[0], $partLength, "\x00", STR_PAD_LEFT) . str_pad($parts[1], $partLength, "\x00", STR_PAD_LEFT);
    }

    private static function clearOpensslErrors(): void
    {
        while (openssl_error_string() !== false) {
            // drain the queue so errors do not leak into unrelated openssl calls
        }
    }
}
