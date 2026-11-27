<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Source;

use Ixbox\EdgeIdentity\Exception\AuthenticationException;
use Ixbox\EdgeIdentity\Exception\TokenMissingException;
use Ixbox\EdgeIdentity\Identity;
use Ixbox\EdgeIdentity\Request\ProxyRequest;

/** Where the identity comes from: ALB header, bearer JWT, trusted headers... */
interface SourceInterface
{
    /**
     * @throws TokenMissingException   when this source finds no credential (not logged in)
     * @throws AuthenticationException when a credential is present but invalid
     */
    public function authenticate(ProxyRequest $request): Identity;
}
