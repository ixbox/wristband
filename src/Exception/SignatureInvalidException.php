<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Exception;

/**
 * The signature does not verify against the public key for the token's kid.
 */
final class SignatureInvalidException extends AuthenticationException
{
}
