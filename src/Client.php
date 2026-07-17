<?php

declare(strict_types=1);

namespace Web3e\Gateway;

/**
 * Thin HTTP client for the Web3e crypto-gateway public REST v1 API.
 *
 * Every call is signed with the v2 scheme (see {@see Signer}). POSTs carry an Idempotency-Key
 * (auto-generated when not supplied). Responses are decoded to an associative array; any error
 * envelope or non-2xx status raises a {@see GatewayException}.
 *
 * Base path is "/rest/gateway/api/v1"; the SIGNED path includes it (the server signs its full
 * request path), so do not strip it.
 */
final class Client
{
    /** @var string */
    private $baseUrl;
    /** @var string */
    private $publicId;
    /** @var Signer */
    private $signer;
    /** @var string */
    private $pathPrefix;
    /** @var int */
    private $timeout;

    /**
     * @param array{path_prefix?:string,timeout?:int} $options
     */
    public function __construct(string $publicId, string $apiSecret, string $baseUrl = 'https://api.web3e.cc', array $options = [])
    {
        $this->publicId = $publicId;
        $this->signer = new Signer($apiSecret);
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->pathPrefix = isset($options['path_prefix']) ? $options['path_prefix'] : '/rest/gateway/api/v1';
        $this->timeout = isset($options['timeout']) ? (int) $options['timeout'] : 30;
    }

    // ── Hosted checkout / payments ────────────────────────────────────────────────────────────

    /** Create a hosted-checkout invoice; the response carries `checkout_url` to redirect the buyer to. */
    public function createInvoice(array $body, ?string $idempotencyKey = null): array
    {
        return $this->post('/invoices', $body, $idempotencyKey);
    }

    /** Create a merchant-rendered payment (you render the pay address yourself; no checkout_url). */
    public function createPayment(array $body, ?string $idempotencyKey = null): array
    {
        return $this->post('/payments', $body, $idempotencyKey);
    }

    public function getPayment(string $id): array
    {
        return $this->get('/payments/' . rawurlencode($id));
    }

    public function getInvoice(string $id): array
    {
        return $this->get('/invoices/' . rawurlencode($id));
    }

    /** @param array<string,scalar> $query */
    public function listPayments(array $query = []): array
    {
        return $this->get('/payments', $query);
    }

    /** @param array<string,scalar> $query amount, currency_from, currency_to */
    public function estimate(array $query): array
    {
        return $this->get('/estimate', $query);
    }

    public function balance(): array
    {
        return $this->get('/balance');
    }

    /** Unsigned health + server clock (use to detect a stale local clock before signing). */
    public function status(): array
    {
        return $this->request('GET', '/status', [], null, false, null);
    }

    // ── HTTP core ─────────────────────────────────────────────────────────────────────────────

    /** @param array<string,scalar> $query */
    private function get(string $path, array $query = []): array
    {
        return $this->request('GET', $path, $query, null, true, null);
    }

    private function post(string $path, array $body, ?string $idempotencyKey): array
    {
        return $this->request('POST', $path, [], $body, true, $idempotencyKey !== null ? $idempotencyKey : self::uuid());
    }

    /**
     * @param array<string,scalar> $query
     * @param array<string,mixed>|null $body
     */
    private function request(string $method, string $path, array $query, ?array $body, bool $signed, ?string $idempotencyKey): array
    {
        $fullPath = $this->pathPrefix . $path;
        $queryString = $query !== [] ? http_build_query($query, '', '&', PHP_QUERY_RFC3986) : '';
        $url = $this->baseUrl . $fullPath . ($queryString !== '' ? '?' . $queryString : '');
        // The bytes we hash MUST equal the bytes we send — serialize once, reuse for both.
        $rawBody = $body !== null ? (string) json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : '';

        $headers = ['Accept: application/json'];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
        }
        if ($signed) {
            foreach ($this->signer->headers($this->publicId, $method, $fullPath, $queryString, $rawBody) as $name => $value) {
                $headers[] = $name . ': ' . $value;
            }
            if ($idempotencyKey !== null) {
                $headers[] = 'Idempotency-Key: ' . $idempotencyKey;
            }
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => 10,
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $rawBody);
        }

        $response = curl_exec($ch);
        if ($response === false) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new GatewayException('HTTP request failed: ' . $error);
        }
        $httpStatus = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        $decoded = json_decode((string) $response, true);
        if (!is_array($decoded)) {
            throw new GatewayException('Invalid JSON response (HTTP ' . $httpStatus . ')', $httpStatus);
        }
        if ($httpStatus >= 400 || isset($decoded['error'])) {
            $envelope = (isset($decoded['error']) && is_array($decoded['error'])) ? $decoded['error'] : [];
            $message = isset($envelope['message']) ? (string) $envelope['message'] : ('HTTP ' . $httpStatus);
            $code = isset($envelope['code']) ? (string) $envelope['code'] : null;
            throw new GatewayException($message, $httpStatus, $code);
        }

        return $decoded;
    }

    /** RFC-4122 v4 UUID (idempotency key fallback). */
    private static function uuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }
}
