<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Tests\Integration;

use Ixbox\EdgeIdentity\Http\HttpException;
use Ixbox\EdgeIdentity\Http\NativeHttpClient;
use PHPUnit\Framework\TestCase;

final class NativeHttpClientTest extends TestCase
{
    /** @var resource|null */
    private static $server;
    /** @var string */
    private static $base = '';

    public static function setUpBeforeClass(): void
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        if ($socket === false) {
            return;
        }
        $name = (string) stream_socket_get_name($socket, false);
        fclose($socket);
        $port = (int) substr($name, strrpos($name, ':') + 1);

        $command = escapeshellarg(PHP_BINARY) . ' -S 127.0.0.1:' . $port . ' ' . escapeshellarg(__DIR__ . '/../Fixtures/http-server.php');
        $process = proc_open($command, [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        if (!is_resource($process)) {
            return;
        }
        self::$server = $process;
        self::$base = 'http://127.0.0.1:' . $port;
        for ($i = 0; $i < 50; $i++) {
            $probe = @fsockopen('127.0.0.1', $port);
            if ($probe !== false) {
                fclose($probe);

                return;
            }
            usleep(100000);
        }
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$server !== null) {
            proc_terminate(self::$server);
            proc_close(self::$server);
            self::$server = null;
        }
    }

    protected function setUp(): void
    {
        if (self::$server === null) {
            self::markTestSkipped('Could not start the PHP built-in server.');
        }
    }

    /** @return array<string, array{0: bool}> */
    public static function transports(): array
    {
        $cases = ['streams' => [false]];
        if (function_exists('curl_init')) {
            $cases['curl'] = [true];
        }

        return $cases;
    }

    /**
     * @dataProvider transports
     */
    public function testFetchesBodyAndStatus(bool $curl): void
    {
        $client = new NativeHttpClient($curl);

        $ok = $client->get(self::$base . '/ok', 2.0, 1024);
        self::assertSame(200, $ok->status());
        self::assertSame("hello\n", $ok->body());

        self::assertSame(404, $client->get(self::$base . '/nope', 2.0, 1024)->status());
    }

    /**
     * @dataProvider transports
     */
    public function testDoesNotFollowRedirects(bool $curl): void
    {
        self::assertSame(302, (new NativeHttpClient($curl))->get(self::$base . '/redirect', 2.0, 1024)->status());
    }

    /**
     * @dataProvider transports
     */
    public function testLimitsBodySize(bool $curl): void
    {
        $this->expectException(HttpException::class);
        (new NativeHttpClient($curl))->get(self::$base . '/big', 2.0, 1000);
    }

    /**
     * @dataProvider transports
     */
    public function testTimesOut(bool $curl): void
    {
        $started = microtime(true);
        try {
            (new NativeHttpClient($curl))->get(self::$base . '/slow', 0.5, 1024);
            self::fail('Expected a timeout');
        } catch (HttpException $e) {
            self::assertLessThan(2.5, microtime(true) - $started);
        }
    }

    public function testRejectsOtherSchemes(): void
    {
        $this->expectException(HttpException::class);
        (new NativeHttpClient())->get('file:///etc/passwd', 1.0, 1024);
    }
}
