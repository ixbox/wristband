<?php

declare(strict_types=1);

namespace Ixbox\EdgeIdentity\Http;

/**
 * Minimal GET client: ext-curl when available, otherwise PHP streams.
 * TLS peers are always verified and redirects are never followed.
 */
final class NativeHttpClient implements HttpClientInterface
{
    /** @var bool */
    private $useCurl;

    public function __construct(?bool $useCurl = null)
    {
        $this->useCurl = $useCurl !== null ? $useCurl : function_exists('curl_init');
    }

    public function get(string $url, float $timeoutSeconds, int $maxBytes): HttpResponse
    {
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if ($scheme !== 'https' && $scheme !== 'http') {
            throw new HttpException('Only http and https URLs can be fetched.');
        }

        return $this->useCurl ? $this->curl($url, $timeoutSeconds, $maxBytes) : $this->stream($url, $timeoutSeconds, $maxBytes);
    }

    private function curl(string $url, float $timeout, int $maxBytes): HttpResponse
    {
        $handle = curl_init($url);
        if ($handle === false) {
            throw new HttpException('curl_init failed.');
        }
        $body = '';
        $tooLarge = false;
        curl_setopt_array($handle, [
            CURLOPT_HTTPGET => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT_MS => (int) ceil($timeout * 1000),
            CURLOPT_TIMEOUT_MS => (int) ceil($timeout * 1000),
            CURLOPT_NOSIGNAL => true,
            CURLOPT_HTTPHEADER => ['Accept: application/json, application/x-pem-file, */*'],
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body, &$tooLarge, $maxBytes): int {
                if (strlen($body) + strlen($chunk) > $maxBytes) {
                    $tooLarge = true;

                    return 0; // abort the transfer
                }
                $body .= $chunk;

                return strlen($chunk);
            },
        ]);
        $ok = curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);
        if (PHP_VERSION_ID < 80000) {
            curl_close($handle);
        }
        if ($tooLarge) {
            throw new HttpException('The response exceeds ' . $maxBytes . ' bytes.');
        }
        if ($ok === false) {
            throw new HttpException('HTTP request failed: ' . $error);
        }

        return new HttpResponse($status, $body);
    }

    private function stream(string $url, float $timeout, int $maxBytes): HttpResponse
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => $timeout,
                'follow_location' => 0,
                'ignore_errors' => true,
                'header' => "Accept: application/json, application/x-pem-file, */*\r\n",
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);

        // Read the status line from the stream metadata: unlike the magic
        // $http_response_header variable, this works the same on PHP 7.2 to 8.x.
        $handle = @fopen($url, 'rb', false, $context);
        if ($handle === false) {
            $error = error_get_last();
            throw new HttpException('HTTP request failed: ' . ($error !== null ? $error['message'] : 'unknown error'));
        }
        $meta = stream_get_meta_data($handle);
        $headers = isset($meta['wrapper_data']) && is_array($meta['wrapper_data']) ? $meta['wrapper_data'] : [];
        $body = stream_get_contents($handle, max(1, $maxBytes + 1));
        $timedOut = (bool) stream_get_meta_data($handle)['timed_out'];
        fclose($handle);
        if ($body === false || $timedOut) {
            throw new HttpException('HTTP request failed: ' . ($timedOut ? 'timed out' : 'read error'));
        }
        if (strlen($body) > $maxBytes) {
            throw new HttpException('The response exceeds ' . $maxBytes . ' bytes.');
        }
        $status = 0;
        foreach ($headers as $line) {
            // With redirects disabled the first status line is the only one.
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', (string) $line, $m) === 1) {
                $status = (int) $m[1];
                break;
            }
        }

        return new HttpResponse($status, $body);
    }
}
