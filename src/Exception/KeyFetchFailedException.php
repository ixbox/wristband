<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Exception;

/**
 * The public key or JWKS for the token could not be obtained (network, HTTP status, unknown kid, backoff after a recent failure).
 */
final class KeyFetchFailedException extends AuthenticationException
{
}
