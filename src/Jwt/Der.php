<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Jwt;

/**
 * The few DER constructs needed for ECDSA signatures and SubjectPublicKeyInfo.
 *
 * @internal
 */
final class Der
{
    public static function sequence(string ...$items): string
    {
        return self::tlv("\x30", implode('', $items));
    }

    /** An unsigned big-endian integer. */
    public static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '' || ord($bytes[0]) > 0x7f) {
            $bytes = "\x00" . $bytes;
        }

        return self::tlv("\x02", $bytes);
    }

    public static function bitString(string $bytes): string
    {
        return self::tlv("\x03", "\x00" . $bytes);
    }

    public static function tlv(string $tag, string $content): string
    {
        return $tag . self::length(strlen($content)) . $content;
    }

    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * Reads an ECDSA-Sig-Value (SEQUENCE { r INTEGER, s INTEGER }) and returns
     * r and s as unsigned big-endian bytes, or null when the input is not one.
     *
     * @return array{0: string, 1: string}|null
     */
    public static function readEcdsaSignature(string $der): ?array
    {
        $offset = 0;
        $sequence = self::read($der, $offset, 0x30);
        if ($sequence === null || $offset !== strlen($der)) {
            return null;
        }
        $inner = 0;
        $r = self::read($sequence, $inner, 0x02);
        $s = self::read($sequence, $inner, 0x02);
        if ($r === null || $s === null || $inner !== strlen($sequence)) {
            return null;
        }

        return [ltrim($r, "\x00"), ltrim($s, "\x00")];
    }

    private static function read(string $data, int &$offset, int $expectedTag): ?string
    {
        $total = strlen($data);
        if ($offset + 2 > $total || ord($data[$offset]) !== $expectedTag) {
            return null;
        }
        $length = ord($data[$offset + 1]);
        $offset += 2;
        if ($length & 0x80) {
            $count = $length & 0x7f;
            if ($count < 1 || $count > 2 || $offset + $count > $total) {
                return null;
            }
            $length = 0;
            for ($i = 0; $i < $count; $i++) {
                $length = ($length << 8) | ord($data[$offset + $i]);
            }
            $offset += $count;
        }
        if ($offset + $length > $total) {
            return null;
        }
        $value = (string) substr($data, $offset, $length);
        $offset += $length;

        return $value;
    }
}
