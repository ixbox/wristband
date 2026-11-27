<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Exception;

/**
 * Unsigned identity headers arrived from a peer that is not trusted (shared secret mismatch or remote address not allowed).
 */
final class UntrustedRequestException extends AuthenticationException
{
}
