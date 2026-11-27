<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Exception;

/**
 * exp (in the header or payload) has passed, beyond the configured leeway.
 */
final class ExpiredException extends AuthenticationException
{
}
