<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Net;

use Ixbox\Wristband\Exception\ConfigurationException;

/** Matches an IPv4/IPv6 address against addresses and CIDR ranges. */
final class IpMatcher
{
    /** @var list<array{0: string, 1: int}> packed network, prefix length */
    private $ranges = [];

    /** @param list<string> $ranges e.g. ["10.0.0.0/8", "172.16.0.0/12", "::1"] */
    public function __construct(array $ranges)
    {
        foreach ($ranges as $range) {
            if (!is_string($range)) {
                throw new ConfigurationException('IP ranges must be strings.');
            }
            $parts = explode('/', trim($range), 2);
            $packed = @inet_pton($parts[0]);
            if ($packed === false) {
                throw new ConfigurationException('Invalid IP address: ' . $range);
            }
            $bits = strlen($packed) * 8;
            $prefix = isset($parts[1]) ? $parts[1] : (string) $bits;
            if (!ctype_digit($prefix) || (int) $prefix > $bits) {
                throw new ConfigurationException('Invalid prefix length: ' . $range);
            }
            $this->ranges[] = [$packed, (int) $prefix];
        }
    }

    public function isEmpty(): bool
    {
        return $this->ranges === [];
    }

    public function matches(string $address): bool
    {
        $packed = @inet_pton($address);
        if ($packed === false) {
            return false;
        }
        foreach ($this->ranges as $range) {
            list($network, $prefix) = $range;
            if (strlen($network) !== strlen($packed)) {
                continue;
            }
            $bytes = intdiv($prefix, 8);
            if (substr($network, 0, $bytes) !== substr($packed, 0, $bytes)) {
                continue;
            }
            $rest = $prefix % 8;
            if ($rest === 0) {
                return true;
            }
            $mask = (0xff << (8 - $rest)) & 0xff;
            if ((ord($network[$bytes]) & $mask) === (ord($packed[$bytes]) & $mask)) {
                return true;
            }
        }

        return false;
    }
}
