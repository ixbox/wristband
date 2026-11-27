<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity;

use Ixbox\EdgeIdentity\Exception\ConfigurationException;

/**
 * Which claims feed Identity::sub(), email(), username() and groups().
 *
 * For username and groups the first claim that is present wins, so one map
 * works for Cognito (cognito:username, cognito:groups) and generic OIDC
 * providers (preferred_username, groups).
 */
final class ClaimMap
{
    /** @var string */
    private $subjectClaim;
    /** @var string */
    private $emailClaim;
    /** @var list<string> */
    private $usernameClaims;
    /** @var list<string> */
    private $groupsClaims;

    /**
     * @param list<string>|null $usernameClaims
     * @param list<string>|null $groupsClaims
     */
    public function __construct(
        string $subjectClaim = 'sub',
        string $emailClaim = 'email',
        ?array $usernameClaims = null,
        ?array $groupsClaims = null
    ) {
        if ($subjectClaim === '' || $emailClaim === '') {
            throw new ConfigurationException('Claim names must not be empty.');
        }
        $this->subjectClaim = $subjectClaim;
        $this->emailClaim = $emailClaim;
        $this->usernameClaims = self::names(
            $usernameClaims !== null ? $usernameClaims : ['cognito:username', 'username', 'preferred_username']
        );
        $this->groupsClaims = self::names(
            $groupsClaims !== null ? $groupsClaims : ['cognito:groups', 'groups']
        );
    }

    public function subjectClaim(): string
    {
        return $this->subjectClaim;
    }

    public function emailClaim(): string
    {
        return $this->emailClaim;
    }

    /** @return list<string> */
    public function usernameClaims(): array
    {
        return $this->usernameClaims;
    }

    /** @return list<string> */
    public function groupsClaims(): array
    {
        return $this->groupsClaims;
    }

    /**
     * @param array<mixed> $names
     * @return list<string>
     */
    private static function names(array $names): array
    {
        $out = [];
        foreach ($names as $name) {
            if (!is_string($name) || $name === '') {
                throw new ConfigurationException('Claim names must be non-empty strings.');
            }
            $out[] = $name;
        }

        return $out;
    }
}
