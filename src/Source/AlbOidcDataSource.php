<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Source;

use Ixbox\Wristband\Alb\AlbTokenVerifier;
use Ixbox\Wristband\Identity;
use Ixbox\Wristband\Request\ProxyRequest;

/**
 * Reads x-amzn-oidc-data set by an ALB authenticate-cognito / authenticate-oidc action.
 *
 * x-amzn-oidc-identity and x-amzn-oidc-accesstoken are deliberately not
 * read: they are not signed.
 */
final class AlbOidcDataSource implements SourceInterface
{
    public const HEADER = 'x-amzn-oidc-data';

    /** @var AlbTokenVerifier */
    private $verifier;

    public function __construct(AlbTokenVerifier $verifier)
    {
        $this->verifier = $verifier;
    }

    public function authenticate(ProxyRequest $request): Identity
    {
        return $this->verifier->verify($request->singleHeader(self::HEADER));
    }
}
