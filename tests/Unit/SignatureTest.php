<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Tests\Unit;

use Ixbox\EdgeIdentity\Exception\KeyFetchFailedException;
use Ixbox\EdgeIdentity\Jwt\JwkConverter;
use Ixbox\EdgeIdentity\Jwt\Signature;
use Ixbox\EdgeIdentity\Testing\KeyPair;
use PHPUnit\Framework\TestCase;

final class SignatureTest extends TestCase
{
    public function testRawDerRoundTripIncludingHighBitsAndLeadingZeros(): void
    {
        $cases = [
            str_repeat("\xff", 64),
            str_repeat("\x00", 31) . "\x01" . str_repeat("\x00", 31) . "\x01",
            "\x00\x80" . str_repeat("\x11", 30) . "\x7f" . str_repeat("\x22", 31),
            random_bytes(64),
        ];
        foreach ($cases as $raw) {
            self::assertSame(bin2hex($raw), bin2hex(Signature::derToRaw(Signature::rawToDer($raw))));
        }
    }

    public function testEs256VerifiesOpensslSignatures(): void
    {
        $key = KeyPair::generate('ES256');
        for ($i = 0; $i < 20; $i++) {
            $input = 'message-' . $i;
            $raw = $key->sign($input);
            self::assertSame(64, strlen($raw));
            self::assertTrue(Signature::verify('ES256', $input, $raw, $key->publicPem()));
            self::assertFalse(Signature::verify('ES256', $input . 'x', $raw, $key->publicPem()));
        }
    }

    public function testEs256RejectsDerEncodedSignature(): void
    {
        $key = KeyPair::generate('ES256');
        $der = Signature::rawToDer($key->sign('m'));
        self::assertFalse(Signature::verify('ES256', 'm', $der, $key->publicPem()));
    }

    public function testRs256(): void
    {
        $key = KeyPair::generate('RS256');
        $sig = $key->sign('m');
        self::assertTrue(Signature::verify('RS256', 'm', $sig, $key->publicPem()));
        self::assertFalse(Signature::verify('RS256', 'n', $sig, $key->publicPem()));
    }

    public function testKeyTypeMustMatchAlgorithm(): void
    {
        $rsa = KeyPair::generate('RS256');
        $this->expectException(KeyFetchFailedException::class);
        Signature::verify('ES256', 'm', str_repeat('a', 64), $rsa->publicPem());
    }

    public function testUnknownAlgorithmNeverVerifies(): void
    {
        $key = KeyPair::generate('RS256');
        self::assertFalse(Signature::verify('HS256', 'm', $key->sign('m'), $key->publicPem()));
        self::assertFalse(Signature::verify('none', 'm', '', $key->publicPem()));
    }

    public function testJwkConversionMatchesOpensslPem(): void
    {
        foreach (['ES256', 'RS256'] as $alg) {
            $key = KeyPair::generate($alg);
            self::assertSame($key->publicPem(), JwkConverter::toPem($key->jwk()), $alg);
        }
    }

    public function testJwkConversionRejectsUnsupportedKeys(): void
    {
        $this->expectException(KeyFetchFailedException::class);
        JwkConverter::toPem(['kty' => 'oct', 'k' => 'c2VjcmV0']);
    }
}
