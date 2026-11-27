<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Tests\Unit;

use Ixbox\Wristband\Alb\AlbConfig;
use Ixbox\Wristband\Alb\AlbTokenVerifier;
use Ixbox\Wristband\Clock\FrozenClock;
use Ixbox\Wristband\Exception\ExpiredException;
use Ixbox\Wristband\Jwt\Base64Url;
use Ixbox\Wristband\Key\StaticKeyProvider;
use PHPUnit\Framework\TestCase;

/**
 * Recorded ALB tokens (tests/Fixtures/alb/*.json) must keep verifying.
 */
final class AlbFixturesTest extends TestCase
{
    /** @return array<string, array{0: array<string, mixed>}> */
    public static function fixtures(): array
    {
        $out = [];
        foreach ((array) glob(__DIR__ . '/../Fixtures/alb/*.json') as $file) {
            $data = json_decode((string) file_get_contents((string) $file), true);
            if (is_array($data)) {
                $out[basename((string) $file)] = [$data];
            }
        }

        return $out;
    }

    /**
     * @dataProvider fixtures
     * @param array<string, mixed> $fixture
     */
    public function testFixtureVerifies(array $fixture): void
    {
        $token = (string) $fixture['token'];
        $header = json_decode((string) Base64Url::decode(explode('.', $token)[0]), true);
        self::assertIsArray($header);

        $clock = new FrozenClock((int) $fixture['verify_at']);
        $verifier = new AlbTokenVerifier(
            new AlbConfig((string) $fixture['signer'], null, (string) $fixture['client']),
            new StaticKeyProvider([(string) $header['kid'] => (string) $fixture['public_key_pem']]),
            $clock
        );

        $identity = $verifier->verify($token);
        foreach ((array) $fixture['expect'] as $claim => $value) {
            self::assertSame($value, $identity->claim((string) $claim), (string) $claim);
        }

        // The same token must be rejected once it is past exp + leeway.
        $clock->set((int) $header['exp'] + 31);
        $this->expectException(ExpiredException::class);
        $verifier->verify($token);
    }
}
