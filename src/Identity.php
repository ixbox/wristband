<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity;

use Ixbox\EdgeIdentity\Exception\TokenMalformedException;

/**
 * The authenticated user as reported by the edge, independent of which
 * source (ALB, bearer JWT, trusted headers) produced it. Immutable.
 */
final class Identity
{
    public const SOURCE_ALB = 'alb';
    public const SOURCE_BEARER = 'bearer';
    public const SOURCE_TRUSTED_HEADERS = 'trusted_headers';

    /** @var string */
    private $source;
    /** @var string */
    private $subject;
    /** @var string|null */
    private $email;
    /** @var bool|null */
    private $emailVerified;
    /** @var string|null */
    private $username;
    /** @var list<string> */
    private $groups;
    /** @var array<string, mixed> */
    private $claims;
    /** @var array<string, mixed> */
    private $header;

    /**
     * @param list<string>         $groups
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header
     */
    public function __construct(
        string $source,
        string $subject,
        ?string $email,
        ?bool $emailVerified,
        ?string $username,
        array $groups,
        array $claims,
        array $header = []
    ) {
        $this->source = $source;
        $this->subject = $subject;
        $this->email = $email;
        $this->emailVerified = $emailVerified;
        $this->username = $username;
        $this->groups = array_values($groups);
        $this->claims = $claims;
        $this->header = $header;
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header
     *
     * @throws TokenMalformedException when the subject claim is missing
     */
    public static function fromClaims(string $source, array $claims, array $header = [], ?ClaimMap $map = null): self
    {
        $map = $map !== null ? $map : new ClaimMap();

        $subject = isset($claims[$map->subjectClaim()]) ? $claims[$map->subjectClaim()] : null;
        if (is_int($subject)) {
            $subject = (string) $subject;
        }
        if (!is_string($subject) || $subject === '') {
            throw new TokenMalformedException('subject_missing', 'The token has no usable subject claim.');
        }

        $email = self::stringClaim($claims, $map->emailClaim());
        $username = null;
        foreach ($map->usernameClaims() as $name) {
            $username = self::stringClaim($claims, $name);
            if ($username !== null) {
                break;
            }
        }

        $groups = [];
        foreach ($map->groupsClaims() as $name) {
            if (array_key_exists($name, $claims)) {
                $groups = self::listClaim($claims[$name]);
                break;
            }
        }

        return new self(
            $source,
            $subject,
            $email,
            self::boolClaim($claims, 'email_verified'),
            $username,
            $groups,
            $claims,
            $header
        );
    }

    /** Which source produced this identity: "alb", "bearer" or "trusted_headers". */
    public function source(): string
    {
        return $this->source;
    }

    public function sub(): string
    {
        return $this->subject;
    }

    public function email(): ?string
    {
        return $this->email;
    }

    /**
     * true / false when the IdP said so (ALB passes the string "true"),
     * null when unknown (e.g. trusted headers).
     */
    public function emailVerified(): ?bool
    {
        return $this->emailVerified;
    }

    public function username(): ?string
    {
        return $this->username;
    }

    /** @return list<string> */
    public function groups(): array
    {
        return $this->groups;
    }

    /** @return array<string, mixed> */
    public function claims(): array
    {
        return $this->claims;
    }

    /**
     * @param mixed $default
     * @return mixed
     */
    public function claim(string $name, $default = null)
    {
        return array_key_exists($name, $this->claims) ? $this->claims[$name] : $default;
    }

    /**
     * The JWT header. For ALB this carries signer, kid, iss, client, exp.
     *
     * @return array<string, mixed>
     */
    public function header(): array
    {
        return $this->header;
    }

    public function issuer(): ?string
    {
        $iss = self::stringClaim($this->claims, 'iss');

        return $iss !== null ? $iss : self::stringClaim($this->header, 'iss');
    }

    /** The earliest exp found in the payload or the header, if any. */
    public function expiresAt(): ?int
    {
        $values = [];
        foreach ([$this->claims, $this->header] as $set) {
            if (isset($set['exp']) && (is_int($set['exp']) || is_float($set['exp']))) {
                $values[] = (int) $set['exp'];
            }
        }

        return $values === [] ? null : min($values);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'source' => $this->source,
            'sub' => $this->subject,
            'email' => $this->email,
            'email_verified' => $this->emailVerified,
            'username' => $this->username,
            'groups' => $this->groups,
            'claims' => $this->claims,
            'header' => $this->header,
        ];
    }

    /** @param array<string, mixed> $claims */
    private static function stringClaim(array $claims, string $name): ?string
    {
        if (!isset($claims[$name])) {
            return null;
        }
        $value = $claims[$name];
        if (is_int($value)) {
            return (string) $value;
        }

        return is_string($value) && $value !== '' ? $value : null;
    }

    /** @param array<string, mixed> $claims */
    private static function boolClaim(array $claims, string $name): ?bool
    {
        if (!array_key_exists($name, $claims)) {
            return null;
        }
        $value = $claims[$name];
        if (is_bool($value)) {
            return $value;
        }
        if ($value === 'true') {
            return true;
        }
        if ($value === 'false') {
            return false;
        }

        return null;
    }

    /**
     * @param mixed $value
     * @return list<string>
     */
    private static function listClaim($value): array
    {
        if (is_string($value)) {
            $value = explode(',', $value);
        }
        if (!is_array($value)) {
            return [];
        }
        $out = [];
        foreach ($value as $item) {
            if (is_string($item) && trim($item) !== '') {
                $out[] = trim($item);
            }
        }

        return $out;
    }
}
