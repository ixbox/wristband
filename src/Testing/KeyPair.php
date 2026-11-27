<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Testing;

use Ixbox\Wristband\Jwt\Base64Url;
use Ixbox\Wristband\Jwt\Signature;

/**
 * A freshly generated signing key. For tests only.
 *
 * @internal
 */
final class KeyPair
{
    /** @var string */
    private $alg;
    /** @var string */
    private $privatePem;
    /** @var string */
    private $publicPem;
    /** @var array<string, mixed> */
    private $details;

    /** @param array<string, mixed> $details */
    private function __construct(string $alg, string $privatePem, string $publicPem, array $details)
    {
        $this->alg = $alg;
        $this->privatePem = $privatePem;
        $this->publicPem = $publicPem;
        $this->details = $details;
    }

    public static function generate(string $alg): self
    {
        if ($alg === Signature::ES256) {
            $options = ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'];
        } elseif ($alg === Signature::RS256) {
            $options = ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048];
        } else {
            throw new \InvalidArgumentException('Unsupported algorithm: ' . $alg);
        }
        $key = openssl_pkey_new($options + ['digest_alg' => 'sha256']);
        if ($key === false || !openssl_pkey_export($key, $privatePem)) {
            throw new \RuntimeException('Key generation failed: ' . (string) openssl_error_string());
        }
        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            throw new \RuntimeException('Key inspection failed.');
        }

        return new self($alg, $privatePem, $details['key'], $details);
    }

    public function alg(): string
    {
        return $this->alg;
    }

    public function publicPem(): string
    {
        return $this->publicPem;
    }

    public function sign(string $input): string
    {
        $key = openssl_pkey_get_private($this->privatePem);
        if ($key === false || !openssl_sign($input, $signature, $key, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('Signing failed.');
        }

        return $this->alg === Signature::ES256 ? Signature::derToRaw($signature) : $signature;
    }

    /** @return array<string, string> the public key as a JWK (without kid) */
    public function jwk(): array
    {
        if ($this->alg === Signature::ES256) {
            return [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => Base64Url::encode(str_pad($this->details['ec']['x'], 32, "\x00", STR_PAD_LEFT)),
                'y' => Base64Url::encode(str_pad($this->details['ec']['y'], 32, "\x00", STR_PAD_LEFT)),
            ];
        }

        return [
            'kty' => 'RSA',
            'n' => Base64Url::encode($this->details['rsa']['n']),
            'e' => Base64Url::encode($this->details['rsa']['e']),
        ];
    }
}
