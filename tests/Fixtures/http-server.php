<?php

// Router for `php -S` used by NativeHttpClientTest.
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
switch ($path) {
    case '/ok':
        header('Content-Type: text/plain');
        echo "hello\n";
        break;
    case '/big':
        echo str_repeat('x', 100000);
        break;
    case '/redirect':
        header('Location: /ok', true, 302);
        echo 'moved';
        break;
    case '/slow':
        sleep(3);
        echo 'late';
        break;
    default:
        http_response_code(404);
        echo 'missing';
}
