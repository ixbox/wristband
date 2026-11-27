<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Exception;

/**
 * Base class for every reason a request could not be authenticated.
 *
 * The concrete class tells the category (for metrics and log filters);
 * reason() gives a stable, machine-readable detail such as "alg_not_allowed".
 * Messages never contain the token itself.
 */
abstract class AuthenticationException extends \RuntimeException
{
    /** @var string */
    private $reason;

    public function __construct(string $reason, string $message = '', ?\Throwable $previous = null)
    {
        $this->reason = $reason;
        parent::__construct($message !== '' ? $message : $reason, 0, $previous);
    }

    public function reason(): string
    {
        return $this->reason;
    }
}
