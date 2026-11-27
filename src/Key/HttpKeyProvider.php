<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Key;

use Ixbox\EdgeIdentity\Exception\ConfigurationException;
use Ixbox\EdgeIdentity\Exception\KeyFetchFailedException;
use Ixbox\EdgeIdentity\Http\HttpClientInterface;
use Ixbox\EdgeIdentity\Http\HttpException;
use Ixbox\EdgeIdentity\Http\NativeHttpClient;

/**
 * Fetches ALB public keys: https://public-keys.auth.elb.{region}.amazonaws.com/{kid}
 *
 * The URL is a template so a test environment or a mock can be used
 * ("http://localhost:8080/keys/{kid}"). A template without "{kid}" gets
 * "/{kid}" appended. Callers must only pass validated kids (AlbTokenVerifier
 * checks the UUID format first); the kid is URL-encoded here as well.
 */
final class HttpKeyProvider implements KeyProviderInterface
{
    public const DEFAULT_URL_TEMPLATE = 'https://public-keys.auth.elb.{region}.amazonaws.com/{kid}';
    private const MAX_BYTES = 16384;

    /** @var string */
    private $urlTemplate;
    /** @var HttpClientInterface */
    private $http;
    /** @var float */
    private $timeout;

    public function __construct(string $urlTemplate, ?HttpClientInterface $http = null, float $timeoutSeconds = 2.0)
    {
        if (str_contains($urlTemplate, '{region}')) {
            throw new ConfigurationException('Resolve {region} first, e.g. with HttpKeyProvider::forRegion().');
        }
        if (!str_contains($urlTemplate, '{kid}')) {
            $urlTemplate = rtrim($urlTemplate, '/') . '/{kid}';
        }
        $this->urlTemplate = $urlTemplate;
        $this->http = $http !== null ? $http : new NativeHttpClient();
        $this->timeout = $timeoutSeconds;
    }

    public static function forRegion(string $region, ?HttpClientInterface $http = null, float $timeoutSeconds = 2.0, string $urlTemplate = self::DEFAULT_URL_TEMPLATE): self
    {
        if (preg_match('/^[a-z]{2}(-[a-z]+)+-\d+$/', $region) !== 1) {
            throw new ConfigurationException('Invalid AWS region: ' . $region);
        }

        return new self(str_replace('{region}', $region, $urlTemplate), $http, $timeoutSeconds);
    }

    public function get(string $kid): string
    {
        $url = str_replace('{kid}', rawurlencode($kid), $this->urlTemplate);
        try {
            $response = $this->http->get($url, $this->timeout, self::MAX_BYTES);
        } catch (HttpException $e) {
            throw new KeyFetchFailedException('key_fetch_error', 'Fetching the ALB public key failed.', $e);
        }
        if ($response->status() !== 200) {
            throw new KeyFetchFailedException('key_fetch_status', 'Fetching the ALB public key returned HTTP ' . $response->status() . '.');
        }
        $pem = trim($response->body()) . "\n";
        if (!str_starts_with($pem, '-----BEGIN PUBLIC KEY-----') || openssl_pkey_get_public($pem) === false) {
            while (openssl_error_string() !== false) {
            }
            throw new KeyFetchFailedException('invalid_public_key', 'The ALB public key endpoint did not return a PEM public key.');
        }

        return $pem;
    }
}
