<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Exception;

/**
 * A claim does not match the configuration: client, iss, aud, token_use, nbf, iat.
 */
final class ClaimInvalidException extends AuthenticationException
{
}
