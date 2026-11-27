<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Exception;

/**
 * The ALB token's signer is not one of the configured load balancer ARNs.
 */
final class SignerMismatchException extends AuthenticationException
{
}
