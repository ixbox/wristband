<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Source;

use Ixbox\EdgeIdentity\Exception\TokenMissingException;
use Ixbox\EdgeIdentity\Exception\UntrustedRequestException;
use Ixbox\EdgeIdentity\Identity;
use Ixbox\EdgeIdentity\Request\ProxyRequest;

/**
 * Trusts plain identity headers set by oauth2-proxy (--pass-user-headers or
 * --set-xauthrequest). NOT RECOMMENDED: nothing is signed. Prefer
 * BearerJwtSource with --pass-authorization-header.
 *
 * Only accepted when the request carries the shared secret header (inject it
 * in oauth2-proxy's injectRequestHeaders) and/or comes from a trusted proxy
 * address. Anyone who can reach the app directly can otherwise log in as
 * anyone.
 */
final class TrustedHeadersSource implements SourceInterface
{
    private const MAX_LENGTH = 4096;

    /** @var TrustedHeadersConfig */
    private $config;

    public function __construct(TrustedHeadersConfig $config)
    {
        $this->config = $config;
    }

    public function authenticate(ProxyRequest $request): Identity
    {
        $userHeader = $this->config->userHeader();
        if (!$request->hasHeader($userHeader)) {
            throw new TokenMissingException('header_missing', 'The ' . $userHeader . ' header is missing.');
        }
        $this->assertTrusted($request);

        $claims = ['sub' => $request->singleHeader($userHeader, self::MAX_LENGTH)];
        $email = $this->optionalHeader($request, $this->config->emailHeader());
        if ($email !== null) {
            $claims['email'] = $email;
        }
        $username = $this->optionalHeader($request, $this->config->usernameHeader());
        if ($username !== null) {
            $claims['preferred_username'] = $username;
        }
        $groups = $this->optionalHeader($request, $this->config->groupsHeader());
        if ($groups !== null) {
            $claims['groups'] = $groups;
        }

        return Identity::fromClaims(Identity::SOURCE_TRUSTED_HEADERS, $claims);
    }

    private function assertTrusted(ProxyRequest $request): void
    {
        $proxies = $this->config->trustedProxies();
        if (!$proxies->isEmpty()) {
            $remote = $request->remoteAddress();
            if ($remote === null || !$proxies->matches($remote)) {
                throw new UntrustedRequestException('untrusted_peer', 'Identity headers arrived from an untrusted address.');
            }
        }

        $secretHeader = $this->config->sharedSecretHeader();
        $secret = $this->config->sharedSecret();
        if ($secretHeader !== null && $secret !== null) {
            $values = $request->headerValues($secretHeader);
            if (count($values) !== 1 || !hash_equals($secret, $values[0])) {
                throw new UntrustedRequestException('shared_secret_mismatch', 'Identity headers arrived without the shared secret.');
            }
        }
    }

    private function optionalHeader(ProxyRequest $request, ?string $name): ?string
    {
        if ($name === null || !$request->hasHeader($name)) {
            return null;
        }

        return $request->singleHeader($name, self::MAX_LENGTH);
    }
}
