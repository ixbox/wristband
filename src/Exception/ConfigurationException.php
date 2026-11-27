<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Exception;

/**
 * The library was configured incorrectly. This is a programming/deployment
 * error, not an authentication failure, so it does not extend
 * AuthenticationException and should not be swallowed as "not logged in".
 */
final class ConfigurationException extends \InvalidArgumentException
{
}
