<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Jwt;

use Ixbox\Wristband\Exception\ClaimInvalidException;
use Ixbox\Wristband\Exception\ExpiredException;
use Ixbox\Wristband\Exception\TokenMalformedException;

/**
 * exp / nbf / iat checks with leeway.
 *
 * @internal
 */
final class TimeClaims
{
    /**
     * @param array<string, mixed> $claims
     * @throws ExpiredException|TokenMalformedException
     */
    public static function assertNotExpired(array $claims, int $now, int $leeway, bool $required, string $where): void
    {
        if (!array_key_exists('exp', $claims)) {
            if ($required) {
                throw new TokenMalformedException('exp_missing', 'The ' . $where . ' has no exp.');
            }

            return;
        }
        $exp = self::numeric($claims['exp'], 'exp', $where);
        if ($now > $exp + $leeway) {
            throw new ExpiredException('expired', 'The token ' . $where . ' has expired.');
        }
    }

    /**
     * @param array<string, mixed> $claims
     * @throws ClaimInvalidException|TokenMalformedException
     */
    public static function assertUsableNow(array $claims, int $now, int $leeway): void
    {
        if (array_key_exists('nbf', $claims) && $now + $leeway < self::numeric($claims['nbf'], 'nbf', 'payload')) {
            throw new ClaimInvalidException('not_yet_valid', 'The token is not valid yet (nbf).');
        }
        if (array_key_exists('iat', $claims) && self::numeric($claims['iat'], 'iat', 'payload') > $now + $leeway) {
            throw new ClaimInvalidException('issued_in_future', 'The token was issued in the future (iat).');
        }
    }

    /** @param mixed $value */
    private static function numeric($value, string $name, string $where): int
    {
        if (is_int($value)) {
            return $value;
        }
        if (is_float($value) && is_finite($value)) {
            return (int) floor($value);
        }
        throw new TokenMalformedException('invalid_' . $name, 'The ' . $where . ' ' . $name . ' is not a number.');
    }
}
