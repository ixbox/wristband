<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Jwt;

/**
 * Reading and matching claim values.
 *
 * @internal
 */
final class ClaimValues
{
    /**
     * Scopes from "scope" (OAuth 2.0, space-separated) or "scp" (string or array, e.g. Entra ID).
     *
     * @param array<string, mixed> $claims
     * @return list<string>
     */
    public static function scopes(array $claims): array
    {
        foreach (['scope', 'scp'] as $name) {
            if (!array_key_exists($name, $claims)) {
                continue;
            }
            $value = $claims[$name];
            $items = is_string($value) ? preg_split('/\s+/', trim($value)) : (is_array($value) ? $value : []);
            $out = [];
            foreach ((array) $items as $item) {
                if (is_string($item) && $item !== '' && !in_array($item, $out, true)) {
                    $out[] = $item;
                }
            }

            return $out;
        }

        return [];
    }

    /**
     * True when the claim equals one of the allowed values. When the claim
     * is an array (e.g. groups), one of its elements must be allowed.
     *
     * @param mixed        $value
     * @param list<string> $allowed
     */
    public static function matches($value, array $allowed): bool
    {
        foreach (is_array($value) ? $value : [$value] as $item) {
            $normalized = self::normalize($item);
            if ($normalized !== null && in_array($normalized, $allowed, true)) {
                return true;
            }
        }

        return false;
    }

    /** @param mixed $value */
    public static function normalize($value): ?string
    {
        if (is_string($value)) {
            return $value;
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_int($value)) {
            return (string) $value;
        }

        return null;
    }
}
