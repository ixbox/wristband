<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Alb;

use Ixbox\Wristband\Exception\ConfigurationException;

/**
 * What an ALB token must look like to be accepted.
 *
 *     new AlbConfig(
 *         'arn:aws:elasticloadbalancing:ap-northeast-1:123:loadbalancer/app/xxx/yyy', // required: signer(s)
 *         'ap-northeast-1',          // optional: derived from the first signer ARN when null
 *         'cognito-app-client-id',   // optional: expected "client" header value(s)
 *         30                         // leeway for exp, in seconds
 *     );
 */
final class AlbConfig
{
    /** @var list<string> */
    private $signerArns;
    /** @var string */
    private $region;
    /** @var list<string> */
    private $clientIds;
    /** @var int */
    private $leeway;
    /** @var string|null */
    private $issuer;
    /** @var int */
    private $maxTokenLength = 16384;

    /**
     * @param string|list<string>      $signerArns one ALB ARN, or several when more than one ALB fronts the app
     * @param string|list<string>|null $clientIds
     */
    public function __construct($signerArns, ?string $region = null, $clientIds = null, int $leeway = 30, ?string $issuer = null)
    {
        $this->signerArns = self::stringList($signerArns, 'signer ARN');
        if ($this->signerArns === []) {
            throw new ConfigurationException('At least one ALB signer ARN is required.');
        }
        if ($region === null || $region === '') {
            $region = self::regionFromArn($this->signerArns[0]);
        }
        if (preg_match('/^[a-z]{2}(-[a-z]+)+-\d+$/', $region) !== 1) {
            throw new ConfigurationException('Invalid AWS region: ' . $region);
        }
        if ($leeway < 0) {
            throw new ConfigurationException('Leeway must not be negative.');
        }
        $this->region = $region;
        $this->clientIds = $clientIds === null ? [] : self::stringList($clientIds, 'client id');
        $this->leeway = $leeway;
        $this->issuer = $issuer !== '' ? $issuer : null;
    }

    /** @return list<string> */
    public function signerArns(): array
    {
        return $this->signerArns;
    }

    public function region(): string
    {
        return $this->region;
    }

    /** @return list<string> empty when the client is not checked */
    public function clientIds(): array
    {
        return $this->clientIds;
    }

    public function leeway(): int
    {
        return $this->leeway;
    }

    public function issuer(): ?string
    {
        return $this->issuer;
    }

    public function maxTokenLength(): int
    {
        return $this->maxTokenLength;
    }

    public function withIssuer(?string $issuer): self
    {
        $clone = clone $this;
        $clone->issuer = $issuer !== '' ? $issuer : null;

        return $clone;
    }

    public function withMaxTokenLength(int $bytes): self
    {
        if ($bytes < 256) {
            throw new ConfigurationException('The maximum token length is unreasonably small.');
        }
        $clone = clone $this;
        $clone->maxTokenLength = $bytes;

        return $clone;
    }

    private static function regionFromArn(string $arn): string
    {
        $parts = explode(':', $arn);
        if (count($parts) < 6 || $parts[0] !== 'arn' || $parts[3] === '') {
            throw new ConfigurationException('Cannot derive the region from the signer ARN; pass the region explicitly.');
        }

        return $parts[3];
    }

    /**
     * @param mixed $value
     * @return list<string>
     */
    private static function stringList($value, string $what): array
    {
        $values = is_array($value) ? $value : [$value];
        $out = [];
        foreach ($values as $item) {
            if (!is_string($item) || trim($item) === '') {
                throw new ConfigurationException('Each ' . $what . ' must be a non-empty string.');
            }
            $out[] = trim($item);
        }

        return $out;
    }
}
