<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Jwt;

use Ixbox\Wristband\Exception\TokenMalformedException;

/**
 * A compact JWS split into its parts. Parsing does not verify anything
 * beyond structure.
 *
 * @internal
 */
final class Jwt
{
    /** @var array<string, mixed> */
    private $header;
    /** @var array<string, mixed> */
    private $payload;
    /** @var string */
    private $signingInput;
    /** @var string */
    private $signature;

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $payload
     */
    private function __construct(array $header, array $payload, string $signingInput, string $signature)
    {
        $this->header = $header;
        $this->payload = $payload;
        $this->signingInput = $signingInput;
        $this->signature = $signature;
    }

    /**
     * @throws TokenMalformedException
     */
    public static function parse(string $token, int $maxLength): self
    {
        if (strlen($token) > $maxLength) {
            throw new TokenMalformedException('too_long', 'The token exceeds the maximum length.');
        }
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new TokenMalformedException('invalid_format', 'A JWT must have exactly three segments.');
        }

        $header = self::decodeJson($parts[0], 'header');
        $payload = self::decodeJson($parts[1], 'payload');
        $signature = Base64Url::decode($parts[2]);
        if ($signature === null) {
            throw new TokenMalformedException('invalid_signature_encoding', 'The signature segment is not base64url.');
        }
        if (isset($header['crit'])) {
            // No critical extensions are supported (RFC 7515 4.1.11).
            throw new TokenMalformedException('crit_not_supported', 'The token uses unsupported critical header parameters.');
        }

        return new self($header, $payload, $parts[0] . '.' . $parts[1], $signature);
    }

    /** @return array<string, mixed> */
    public function header(): array
    {
        return $this->header;
    }

    /** @return array<string, mixed> */
    public function payload(): array
    {
        return $this->payload;
    }

    /** The exact bytes that were signed: the first two segments as transmitted. */
    public function signingInput(): string
    {
        return $this->signingInput;
    }

    /** The raw (decoded) signature bytes. */
    public function signature(): string
    {
        return $this->signature;
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodeJson(string $segment, string $part): array
    {
        $json = Base64Url::decode($segment);
        if ($json === null) {
            throw new TokenMalformedException('invalid_' . $part . '_encoding', 'The ' . $part . ' segment is not base64url.');
        }
        $json = ltrim($json);
        $data = json_decode($json, true, 32, JSON_BIGINT_AS_STRING);
        // Require a JSON object; a JSON array would also decode to a PHP array.
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($data) || ($json[0] ?? '') !== '{') {
            throw new TokenMalformedException('invalid_' . $part . '_json', 'The ' . $part . ' is not a JSON object.');
        }

        /** @var array<string, mixed> $data */
        return $data;
    }
}
