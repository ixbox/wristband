<?php

declare(strict_types=1);

namespace Ixbox\Wristband\Tests\Support;

use Ixbox\Wristband\Http\HttpClientInterface;
use Ixbox\Wristband\Http\HttpException;
use Ixbox\Wristband\Http\HttpResponse;

final class FakeHttpClient implements HttpClientInterface
{
    /** @var array<string, HttpResponse|HttpException> */
    public $routes = [];
    /** @var list<string> */
    public $requests = [];

    /** @param HttpResponse|HttpException $response */
    public function on(string $url, $response): self
    {
        $this->routes[$url] = $response;

        return $this;
    }

    public function get(string $url, float $timeoutSeconds, int $maxBytes): HttpResponse
    {
        $this->requests[] = $url;
        if (!isset($this->routes[$url])) {
            return new HttpResponse(404, 'not found');
        }
        $response = $this->routes[$url];
        if ($response instanceof HttpException) {
            throw $response;
        }

        return $response;
    }
}
