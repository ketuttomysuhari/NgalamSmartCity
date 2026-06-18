<?php
/**
 * CCTV HTTPS/mixed-content proxy for Dashboard Geo Futuristik
 * Usage: cctv_proxy.php?url=http%3A%2F%2Fstream.cctv.malangkota.go.id%2FWebRTCApp%2Fplay.html%3Fname%3D...
 *
 * Security: this proxy is restricted to stream.cctv.malangkota.go.id only.
 */

$allowedHost = 'stream.cctv.malangkota.go.id';
$origin = 'http://' . $allowedHost;

function deny($message, $code = 400) {
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    echo $message;
    exit;
}

$url = $_GET['url'] ?? '';
if (!$url) {
    deny('Missing url parameter.');
}

$parts = parse_url($url);
if (!$parts || !isset($parts['host']) || strtolower($parts['host']) !== $allowedHost) {
    deny('Blocked: only ' . $allowedHost . ' is allowed.', 403);
}

if (!in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true)) {
    deny('Blocked: invalid URL scheme.', 403);
}

$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => 60,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_HEADER => true,
    CURLOPT_HTTPHEADER => [
        'User-Agent: Mozilla/5.0 CCTV Dashboard Proxy',
        'Accept: */*',
        'Connection: keep-alive'
    ],
]);

$response = curl_exec($ch);
if ($response === false) {
    deny('Proxy error: ' . curl_error($ch), 502);
}

$headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE) ?: 'text/html; charset=utf-8';
$statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE) ?: 200;
$body = substr($response, $headerSize);
curl_close($ch);

http_response_code($statusCode);
header('Content-Type: ' . $contentType);
header('Access-Control-Allow-Origin: *');
header('X-Frame-Options: ALLOWALL');
header("Content-Security-Policy: frame-ancestors *; default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; img-src * data: blob:; media-src * data: blob:; connect-src * ws: wss: http: https:;");
header('Referrer-Policy: no-referrer');

$isText = preg_match('/(text|javascript|json|xml|html|css)/i', $contentType);
if ($isText) {
    $baseUrl = $parts['scheme'] . '://' . $parts['host'];
    $path = $parts['path'] ?? '/';
    $dir = rtrim(dirname($path), '/\\');
    $dirUrl = $baseUrl . ($dir === '' ? '' : $dir) . '/';

    $proxyUrl = function ($asset) use ($baseUrl, $dirUrl, $origin) {
        $asset = trim($asset);
        if ($asset === '' || str_starts_with($asset, 'data:') || str_starts_with($asset, 'blob:') || str_starts_with($asset, 'javascript:') || str_starts_with($asset, '#')) {
            return $asset;
        }
        if (str_starts_with($asset, '//')) {
            $absolute = 'http:' . $asset;
        } elseif (preg_match('#^https?://#i', $asset)) {
            $absolute = $asset;
        } elseif (str_starts_with($asset, '/')) {
            $absolute = $baseUrl . $asset;
        } else {
            $absolute = $dirUrl . $asset;
        }
        $host = parse_url($absolute, PHP_URL_HOST);
        if (strtolower((string)$host) !== 'stream.cctv.malangkota.go.id') {
            return $asset;
        }
        return 'cctv_proxy.php?url=' . rawurlencode($absolute);
    };

    // Rewrite common HTML attributes to pass through this proxy.
    $body = preg_replace_callback('/\b(src|href|action)=("|\')(.*?)(\2)/i', function ($m) use ($proxyUrl) {
        return $m[1] . '=' . $m[2] . htmlspecialchars($proxyUrl(htmlspecialchars_decode($m[3])), ENT_QUOTES) . $m[4];
    }, $body);

    // Rewrite CSS url(...).
    $body = preg_replace_callback('/url\(([^)]+)\)/i', function ($m) use ($proxyUrl) {
        $raw = trim($m[1], " \t\n\r\0\x0B'\"");
        return 'url(' . $proxyUrl($raw) . ')';
    }, $body);

    // Rewrite explicit original host references.
    $body = str_replace($origin, 'cctv_proxy.php?url=' . rawurlencode($origin), $body);
}

echo $body;
