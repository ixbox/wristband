<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Tests\Unit;

use Ixbox\Wristband\Jwt\Base64Url;
use PHPUnit\Framework\TestCase;

final class Base64UrlTest extends TestCase
{
    public function testRoundTripWithAndWithoutPadding(): void
    {
        foreach (['', 'a', 'ab', 'abc', "\xff\xfe\xfd", random_bytes(33)] as $data) {
            if ($data === '') {
                continue;
            }
            self::assertSame($data, Base64Url::decode(Base64Url::encode($data)));
            self::assertSame($data, Base64Url::decode(Base64Url::encode($data, true)));
        }
    }

    public function testUsesUrlSafeAlphabet(): void
    {
        self::assertSame('-_8', Base64Url::encode("\xfb\xff"));
        self::assertSame('-_8=', Base64Url::encode("\xfb\xff", true));
    }

    public function testAcceptsStandardAlphabet(): void
    {
        self::assertSame("\xfb\xff", Base64Url::decode('+/8='));
    }

    public function testRejectsInvalidInput(): void
    {
        self::assertNull(Base64Url::decode(''));
        self::assertNull(Base64Url::decode('a'));
        self::assertNull(Base64Url::decode('ab$c'));
        self::assertNull(Base64Url::decode('ab c'));
        self::assertNull(Base64Url::decode('ab,c'));
    }
}
