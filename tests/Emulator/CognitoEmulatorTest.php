<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Tests\Emulator;

use Ixbox\Wristband\Bearer\BearerConfig;
use Ixbox\Wristband\Bearer\BearerTokenVerifier;
use Ixbox\Wristband\Exception\ClaimInvalidException;
use Ixbox\Wristband\Exception\KeyFetchFailedException;
use Ixbox\Wristband\Exception\SignatureInvalidException;
use Ixbox\Wristband\Http\NativeHttpClient;
use Ixbox\Wristband\Identity;
use Ixbox\Wristband\Jwks\HttpJwksProvider;
use Ixbox\Wristband\Jwt\Base64Url;
use Ixbox\Wristband\Request\ProxyRequest;
use Ixbox\Wristband\Source\BearerJwtSource;
use PHPUnit\Framework\TestCase;

/**
 * Verifies tokens issued by the Cognito of AWS Emulator
 * (https://github.com/aws/aws-emulator), fetching discovery and the JWKS over
 * HTTPS with the emulator's own CA.
 *
 * Skipped unless WRISTBAND_EMULATOR_* is set; tests/Emulator/setup-cognito.sh
 * creates the resources and prints the variables. CI runs it in the
 * "AWS Emulator" job with WRISTBAND_EMULATOR_REQUIRED=1, which turns the skip
 * into a failure.
 */
final class CognitoEmulatorTest extends TestCase
{
    /** @var array<string, string> */
    private static $env = [];
    /** @var array<string, string> */
    private static $tokens = [];

    public static function setUpBeforeClass(): void
    {
        $names = ['ENDPOINT', 'CA', 'POOL', 'DOMAIN', 'WEB_CLIENT', 'M2M_CLIENT', 'M2M_SECRET', 'USERNAME', 'PASSWORD'];
        foreach ($names as $name) {
            $value = getenv('WRISTBAND_EMULATOR_' . $name);
            if (!is_string($value) || $value === '') {
                return;
            }
            self::$env[$name] = $value;
        }

        $auth = self::post('/', (string) json_encode([
            'AuthFlow' => 'USER_PASSWORD_AUTH',
            'ClientId' => self::$env['WEB_CLIENT'],
            'AuthParameters' => ['USERNAME' => self::$env['USERNAME'], 'PASSWORD' => self::$env['PASSWORD']],
        ]), [
            'Content-Type: application/x-amz-json-1.1',
            'X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth',
        ]);
        self::$tokens['id'] = (string) $auth['AuthenticationResult']['IdToken'];
        self::$tokens['access'] = (string) $auth['AuthenticationResult']['AccessToken'];

        $m2m = self::post('/' . self::$env['DOMAIN'] . '/oauth2/token', 'grant_type=client_credentials&scope=orders%2Fread', [
            'Content-Type: application/x-www-form-urlencoded',
            'Authorization: Basic ' . base64_encode(self::$env['M2M_CLIENT'] . ':' . self::$env['M2M_SECRET']),
        ]);
        self::$tokens['m2m'] = (string) $m2m['access_token'];
    }

    protected function setUp(): void
    {
        if (self::$tokens === []) {
            if (getenv('WRISTBAND_EMULATOR_REQUIRED') === '1') {
                self::fail('WRISTBAND_EMULATOR_REQUIRED is set but WRISTBAND_EMULATOR_* is incomplete.');
            }
            self::markTestSkipped('AWS Emulator is not configured (WRISTBAND_EMULATOR_*).');
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
    public function testIdTokenThroughDiscoveryAndJwks(bool $curl): void
    {
        $identity = $this->authenticate($this->config(self::$env['WEB_CLIENT'], 'id'), self::$tokens['id'], $curl);

        self::assertSame(Identity::SOURCE_BEARER, $identity->source());
        self::assertSame(self::$env['USERNAME'], $identity->email());
        self::assertTrue($identity->emailVerified());
        self::assertSame($this->issuer(), $identity->issuer());
        self::assertNotNull($identity->username());
    }

    /**
     * @dataProvider transports
     */
    public function testServerCertificateIsVerified(bool $curl): void
    {
        // Without the emulator's CA the self-signed certificate must not be trusted.
        $jwks = HttpJwksProvider::fromIssuer($this->issuer(), new NativeHttpClient($curl));
        $source = new BearerJwtSource(new BearerTokenVerifier($this->config(self::$env['WEB_CLIENT'], 'id'), $jwks));

        $this->expectException(KeyFetchFailedException::class);
        $source->authenticate(ProxyRequest::fromArray(['Authorization' => 'Bearer ' . self::$tokens['id']]));
    }

    public function testMachineToMachineToken(): void
    {
        $config = $this->config(self::$env['M2M_CLIENT'], 'access');
        $identity = $this->authenticate($config->withRequiredScopes(['orders/read']), self::$tokens['m2m']);

        self::assertSame(self::$env['M2M_CLIENT'], $identity->clientId());
        self::assertSame(['orders/read'], $identity->scopes());
        self::assertNull($identity->email());

        $this->assertRejected('scope_missing', $config->withRequiredScopes(['orders/write']), self::$tokens['m2m']);
    }

    public function testMismatchesAreRejected(): void
    {
        $this->assertRejected('token_use_mismatch', $this->config(self::$env['WEB_CLIENT'], 'id'), self::$tokens['access']);
        $this->assertRejected('audience_mismatch', $this->config(self::$env['WEB_CLIENT'], 'access'), self::$tokens['m2m']);
        $this->assertRejected('audience_mismatch', $this->config(self::$env['M2M_CLIENT'], 'access'), self::$tokens['access']);
        $this->assertRejected('issuer_mismatch', new BearerConfig($this->issuer() . 'x', self::$env['WEB_CLIENT'], ['RS256']), self::$tokens['id']);
    }

    public function testTamperedTokenFailsAgainstTheRealKey(): void
    {
        $parts = explode('.', self::$tokens['id']);
        $payload = json_decode((string) Base64Url::decode($parts[1]), true);
        self::assertIsArray($payload);
        $payload['email'] = 'someone-else@example.com';
        $parts[1] = Base64Url::encode((string) json_encode($payload));

        $this->expectException(SignatureInvalidException::class);
        $this->authenticate($this->config(self::$env['WEB_CLIENT'], 'id'), implode('.', $parts));
    }

    private function issuer(): string
    {
        return rtrim(self::$env['ENDPOINT'], '/') . '/' . self::$env['POOL'];
    }

    private function config(string $audience, string $tokenUse): BearerConfig
    {
        return new BearerConfig($this->issuer(), $audience, ['RS256'], 30, $tokenUse);
    }

    private function authenticate(BearerConfig $config, string $token, bool $curl = true): Identity
    {
        $http = new NativeHttpClient($curl && function_exists('curl_init'), self::$env['CA']);
        $jwks = HttpJwksProvider::fromIssuer($this->issuer(), $http);
        $source = new BearerJwtSource(new BearerTokenVerifier($config, $jwks));

        return $source->authenticate(ProxyRequest::fromArray(['Authorization' => 'Bearer ' . $token]));
    }

    private function assertRejected(string $reason, BearerConfig $config, string $token): void
    {
        try {
            $this->authenticate($config, $token);
            self::fail('Expected ' . $reason);
        } catch (ClaimInvalidException $e) {
            self::assertSame($reason, $e->reason());
        }
    }

    /**
     * @param list<string> $headers
     * @return array<string, mixed>
     */
    private static function post(string $path, string $body, array $headers): array
    {
        $context = stream_context_create([
            'http' => ['method' => 'POST', 'header' => implode("\r\n", $headers) . "\r\n", 'content' => $body, 'ignore_errors' => true, 'timeout' => 10],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'cafile' => self::$env['CA']],
        ]);
        $response = file_get_contents(rtrim(self::$env['ENDPOINT'], '/') . $path, false, $context);
        $data = is_string($response) ? json_decode($response, true) : null;
        if (!is_array($data)) {
            throw new \RuntimeException('Unexpected response from the emulator: ' . var_export($response, true));
        }

        return $data;
    }
}
