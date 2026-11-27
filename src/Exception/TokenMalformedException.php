<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Exception;

/**
 * The credential is structurally invalid: not three segments, bad base64/JSON, too long, sent more than once, disallowed alg, bad kid, missing required claim.
 */
final class TokenMalformedException extends AuthenticationException
{
}
