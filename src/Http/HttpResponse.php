<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Http;

final class HttpResponse
{
    /** @var int */
    private $status;
    /** @var string */
    private $body;

    public function __construct(int $status, string $body)
    {
        $this->status = $status;
        $this->body = $body;
    }

    public function status(): int
    {
        return $this->status;
    }

    public function body(): string
    {
        return $this->body;
    }
}
