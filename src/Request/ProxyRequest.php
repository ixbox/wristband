<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Request;

use Ixbox\EdgeIdentity\Exception\TokenMalformedException;
use Ixbox\EdgeIdentity\Exception\TokenMissingException;

/**
 * The parts of an HTTP request a source needs: headers (case-insensitive,
 * possibly repeated) and the address of the direct peer.
 *
 * Build it from whatever the framework offers:
 *   ProxyRequest::fromArray(['x-amzn-oidc-data' => $value]);
 *   ProxyRequest::fromGlobals();                  // $_SERVER
 *   ProxyRequest::fromHttpFoundation($request);   // Symfony HttpFoundation / Laravel
 *   ProxyRequest::fromPsr7($serverRequest);       // PSR-7
 */
final class ProxyRequest
{
    public const DEFAULT_MAX_HEADER_LENGTH = 16384;

    /** @var array<string, list<string>> lower-cased name => values */
    private $headers;
    /** @var string|null */
    private $remoteAddress;

    /**
     * @param array<string, list<string>> $headers
     */
    private function __construct(array $headers, ?string $remoteAddress)
    {
        $this->headers = $headers;
        $this->remoteAddress = $remoteAddress !== '' ? $remoteAddress : null;
    }

    /**
     * @param array<string, string|array<int, string>> $headers
     */
    public static function fromArray(array $headers, ?string $remoteAddress = null): self
    {
        $normalized = [];
        foreach ($headers as $name => $values) {
            $name = strtolower((string) $name);
            foreach (is_array($values) ? $values : [$values] as $value) {
                if (is_scalar($value)) {
                    $normalized[$name][] = (string) $value;
                }
            }
        }

        return new self($normalized, $remoteAddress);
    }

    /**
     * From $_SERVER (or a compatible array). Note that PHP joins repeated
     * headers into one value or keeps only the last; JWT verification still
     * rejects joined values because "," is not a base64url character.
     *
     * @param array<string, mixed>|null $server
     */
    public static function fromGlobals(?array $server = null): self
    {
        $server = $server !== null ? $server : $_SERVER;
        $headers = [];
        foreach ($server as $key => $value) {
            if (!is_string($value)) {
                continue;
            }
            if (str_starts_with((string) $key, 'HTTP_')) {
                $headers[str_replace('_', '-', strtolower(substr((string) $key, 5)))] = [$value];
            }
        }
        // Apache may hide Authorization from HTTP_*.
        if (!isset($headers['authorization']) && isset($server['REDIRECT_HTTP_AUTHORIZATION']) && is_string($server['REDIRECT_HTTP_AUTHORIZATION'])) {
            $headers['authorization'] = [$server['REDIRECT_HTTP_AUTHORIZATION']];
        }
        $remote = isset($server['REMOTE_ADDR']) && is_string($server['REMOTE_ADDR']) ? $server['REMOTE_ADDR'] : null;

        return new self($headers, $remote);
    }

    /**
     * From a Symfony HttpFoundation Request (also Laravel).
     * Uses REMOTE_ADDR, not getClientIp(): what matters for trusting
     * headers is the peer that delivered them.
     *
     * @param object $request Symfony\Component\HttpFoundation\Request
     */
    public static function fromHttpFoundation($request): self
    {
        if (!is_object($request) || !isset($request->headers, $request->server)) {
            throw new \InvalidArgumentException('Expected a Symfony HttpFoundation Request.');
        }
        /** @var array<string, array<int, string>> $all */
        $all = $request->headers->all();
        $remote = $request->server->get('REMOTE_ADDR');

        return self::fromArray($all, is_string($remote) ? $remote : null);
    }

    public static function fromPsr7(\Psr\Http\Message\MessageInterface $request): self
    {
        $remote = null;
        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            $params = $request->getServerParams();
            $remote = isset($params['REMOTE_ADDR']) && is_string($params['REMOTE_ADDR']) ? $params['REMOTE_ADDR'] : null;
        }

        return self::fromArray($request->getHeaders(), $remote);
    }

    /** @return list<string> */
    public function headerValues(string $name): array
    {
        $name = strtolower($name);

        return isset($this->headers[$name]) ? $this->headers[$name] : [];
    }

    public function hasHeader(string $name): bool
    {
        foreach ($this->headerValues($name) as $value) {
            if (trim($value) !== '') {
                return true;
            }
        }

        return false;
    }

    /**
     * The single value of a header.
     *
     * @throws TokenMissingException   when absent or empty
     * @throws TokenMalformedException when sent more than once or too long
     */
    public function singleHeader(string $name, int $maxLength = self::DEFAULT_MAX_HEADER_LENGTH): string
    {
        $values = array_values(array_filter($this->headerValues($name), static function (string $value): bool {
            return trim($value) !== '';
        }));
        if ($values === []) {
            throw new TokenMissingException('header_missing', 'The ' . $name . ' header is missing.');
        }
        if (count($values) > 1) {
            throw new TokenMalformedException('multiple_headers', 'The ' . $name . ' header was sent more than once.');
        }
        if (strlen($values[0]) > $maxLength) {
            throw new TokenMalformedException('header_too_long', 'The ' . $name . ' header is too long.');
        }

        return trim($values[0]);
    }

    public function remoteAddress(): ?string
    {
        return $this->remoteAddress;
    }
}
