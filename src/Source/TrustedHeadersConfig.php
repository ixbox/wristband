<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Source;

use Ixbox\Wristband\Exception\ConfigurationException;
use Ixbox\Wristband\Net\IpMatcher;

/**
 * Settings for TrustedHeadersSource.
 *
 *     new TrustedHeadersConfig([
 *         'preset'               => 'x-forwarded',      // or 'x-auth-request'
 *         'shared_secret_header' => 'X-Edge-Auth-Secret',
 *         'shared_secret'        => getenv('EDGE_AUTH_SECRET'),
 *         'trusted_proxies'      => ['10.0.0.0/8'],      // optional, in addition to or instead of the secret
 *     ]);
 *
 * A shared secret, trusted proxies, or both are mandatory.
 */
final class TrustedHeadersConfig
{
    private const PRESETS = [
        'x-forwarded' => [
            'user_header' => 'X-Forwarded-User',
            'email_header' => 'X-Forwarded-Email',
            'username_header' => 'X-Forwarded-Preferred-Username',
            'groups_header' => 'X-Forwarded-Groups',
        ],
        'x-auth-request' => [
            'user_header' => 'X-Auth-Request-User',
            'email_header' => 'X-Auth-Request-Email',
            'username_header' => 'X-Auth-Request-Preferred-Username',
            'groups_header' => 'X-Auth-Request-Groups',
        ],
    ];
    private const MIN_SECRET_LENGTH = 16;

    /** @var string */
    private $userHeader;
    /** @var string|null */
    private $emailHeader;
    /** @var string|null */
    private $usernameHeader;
    /** @var string|null */
    private $groupsHeader;
    /** @var string|null */
    private $sharedSecretHeader;
    /** @var string|null */
    private $sharedSecret;
    /** @var IpMatcher */
    private $trustedProxies;

    /**
     * @param array{
     *     preset?: string,
     *     user_header?: string,
     *     email_header?: string|null,
     *     username_header?: string|null,
     *     groups_header?: string|null,
     *     shared_secret_header?: string|null,
     *     shared_secret?: string|null,
     *     trusted_proxies?: list<string>|string|null
     * } $options
     */
    public function __construct(array $options)
    {
        $known = ['preset', 'user_header', 'email_header', 'username_header', 'groups_header', 'shared_secret_header', 'shared_secret', 'trusted_proxies'];
        $unknown = array_diff(array_keys($options), $known);
        if ($unknown !== []) {
            throw new ConfigurationException('Unknown trusted headers option(s): ' . implode(', ', $unknown));
        }
        $preset = isset($options['preset']) ? $options['preset'] : 'x-forwarded';
        if (!isset(self::PRESETS[$preset])) {
            throw new ConfigurationException('Unknown preset: ' . $preset);
        }
        $options += self::PRESETS[$preset];

        $user = $options['user_header'];
        if (!is_string($user) || $user === '') {
            throw new ConfigurationException('user_header is required.');
        }
        $this->userHeader = $user;
        $this->emailHeader = self::optional($options['email_header']);
        $this->usernameHeader = self::optional($options['username_header']);
        $this->groupsHeader = self::optional($options['groups_header']);

        $this->sharedSecretHeader = self::optional(isset($options['shared_secret_header']) ? $options['shared_secret_header'] : null);
        $this->sharedSecret = self::optional(isset($options['shared_secret']) ? $options['shared_secret'] : null);
        if (($this->sharedSecretHeader === null) !== ($this->sharedSecret === null)) {
            throw new ConfigurationException('shared_secret_header and shared_secret must be set together.');
        }
        if ($this->sharedSecret !== null && strlen($this->sharedSecret) < self::MIN_SECRET_LENGTH) {
            throw new ConfigurationException('shared_secret must be at least ' . self::MIN_SECRET_LENGTH . ' characters.');
        }

        $proxies = isset($options['trusted_proxies']) ? $options['trusted_proxies'] : [];
        if (is_string($proxies)) {
            $proxies = array_values(array_filter(array_map('trim', explode(',', $proxies)), static function (string $value): bool {
                return $value !== '';
            }));
        }
        $this->trustedProxies = new IpMatcher($proxies);

        if ($this->sharedSecret === null && $this->trustedProxies->isEmpty()) {
            throw new ConfigurationException(
                'Trusted headers are unsigned: configure shared_secret_header/shared_secret, trusted_proxies, or both.'
            );
        }
    }

    public function userHeader(): string
    {
        return $this->userHeader;
    }

    public function emailHeader(): ?string
    {
        return $this->emailHeader;
    }

    public function usernameHeader(): ?string
    {
        return $this->usernameHeader;
    }

    public function groupsHeader(): ?string
    {
        return $this->groupsHeader;
    }

    public function sharedSecretHeader(): ?string
    {
        return $this->sharedSecretHeader;
    }

    public function sharedSecret(): ?string
    {
        return $this->sharedSecret;
    }

    public function trustedProxies(): IpMatcher
    {
        return $this->trustedProxies;
    }

    /** @param mixed $value */
    private static function optional($value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
