<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Source;

use Ixbox\Wristband\Exception\AuthenticationException;
use Ixbox\Wristband\Exception\TokenMissingException;
use Ixbox\Wristband\Identity;
use Ixbox\Wristband\Request\ProxyRequest;

/** Where the identity comes from: ALB header, bearer JWT, trusted headers... */
interface SourceInterface
{
    /**
     * @throws TokenMissingException   when this source finds no credential (not logged in)
     * @throws AuthenticationException when a credential is present but invalid
     */
    public function authenticate(ProxyRequest $request): Identity;
}
