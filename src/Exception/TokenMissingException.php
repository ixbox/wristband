<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Exception;

/**
 * No credential was presented (header absent, empty, or a different auth scheme). Treat as "not logged in"; a ChainSource moves on to the next source.
 */
final class TokenMissingException extends AuthenticationException
{
}
