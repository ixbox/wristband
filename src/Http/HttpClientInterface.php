<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Http;

interface HttpClientInterface
{
    /**
     * Performs a GET without following redirects.
     *
     * @throws HttpException on transport errors, timeouts or oversize bodies
     *                       (not on non-2xx statuses: those are returned)
     */
    public function get(string $url, float $timeoutSeconds, int $maxBytes): HttpResponse;
}
