<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Testing;

use Ixbox\Wristband\Alb\AlbConfig;
use Ixbox\Wristband\Alb\AlbTokenVerifier;
use Ixbox\Wristband\Clock\ClockInterface;
use Ixbox\Wristband\Clock\SystemClock;
use Ixbox\Wristband\Jwt\Base64Url;
use Ixbox\Wristband\Jwt\Signature;
use Ixbox\Wristband\Key\StaticKeyProvider;

/**
 * Issues tokens in the exact shape an ALB puts in x-amzn-oidc-data:
 * ES256 (R || S), padded base64url, header {alg, kid, signer, iss, client, exp}.
 *
 * FOR TESTS ONLY. Never wire this into production code.
 *
 *     $alb = new AlbTokenFactory();
 *     $verifier = $alb->verifier();
 *     $identity = $verifier->verify($alb->issue(['email' => 'a@example.com']));
 */
final class AlbTokenFactory
{
    public const DEFAULT_SIGNER = 'arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:loadbalancer/app/test-alb/0123456789abcdef';
    public const DEFAULT_CLIENT = 'test-client-id';
    public const DEFAULT_ISSUER = 'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_TEST';

    /** @var KeyPair */
    private $key;
    /** @var string */
    private $kid;
    /** @var string */
    private $signer;
    /** @var string */
    private $clientId;
    /** @var string */
    private $issuer;
    /** @var ClockInterface */
    private $clock;

    public function __construct(
        string $signer = self::DEFAULT_SIGNER,
        string $clientId = self::DEFAULT_CLIENT,
        string $issuer = self::DEFAULT_ISSUER,
        ?ClockInterface $clock = null,
        ?string $kid = null
    ) {
        $this->key = KeyPair::generate(Signature::ES256);
        $this->kid = $kid !== null ? $kid : self::uuid();
        $this->signer = $signer;
        $this->clientId = $clientId;
        $this->issuer = $issuer;
        $this->clock = $clock !== null ? $clock : new SystemClock();
    }

    /**
     * @param array<string, mixed> $claims merged over the default payload (null values remove a claim)
     * @param array<string, mixed> $header merged over the default header (null values remove a member)
     */
    public function issue(array $claims = [], array $header = [], int $ttlSeconds = 120): string
    {
        $exp = $this->clock->now() + $ttlSeconds;
        $sub = isset($claims['sub']) && is_string($claims['sub']) ? $claims['sub'] : self::uuid();
        $payload = self::merge([
            'sub' => $sub,
            'email_verified' => 'true',
            'email' => 'user@example.com',
            'username' => $sub,
            'exp' => $exp,
            'iss' => $this->issuer,
        ], $claims);
        $head = self::merge([
            'typ' => 'JWT',
            'kid' => $this->kid,
            'alg' => 'ES256',
            'iss' => $this->issuer,
            'client' => $this->clientId,
            'signer' => $this->signer,
            'exp' => $exp,
        ], $header);

        $input = self::segment($head) . '.' . self::segment($payload);

        return $input . '.' . Base64Url::encode($this->key->sign($input), true);
    }

    public function kid(): string
    {
        return $this->kid;
    }

    public function signer(): string
    {
        return $this->signer;
    }

    public function clientId(): string
    {
        return $this->clientId;
    }

    public function issuer(): string
    {
        return $this->issuer;
    }

    public function publicKeyPem(): string
    {
        return $this->key->publicPem();
    }

    public function keyProvider(): StaticKeyProvider
    {
        return new StaticKeyProvider([$this->kid => $this->key->publicPem()]);
    }

    public function config(int $leeway = 30): AlbConfig
    {
        return new AlbConfig($this->signer, null, $this->clientId, $leeway);
    }

    public function verifier(?ClockInterface $clock = null): AlbTokenVerifier
    {
        return new AlbTokenVerifier($this->config(), $this->keyProvider(), $clock !== null ? $clock : $this->clock);
    }

    /** @param array<string, mixed> $data */
    private static function segment(array $data): string
    {
        return Base64Url::encode((string) json_encode($data, JSON_UNESCAPED_SLASHES), true);
    }

    /**
     * @param array<string, mixed> $base
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private static function merge(array $base, array $overrides): array
    {
        foreach ($overrides as $name => $value) {
            if ($value === null) {
                unset($base[$name]);
            } else {
                $base[$name] = $value;
            }
        }

        return $base;
    }

    private static function uuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }
}
