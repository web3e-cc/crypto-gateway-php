<?php

declare(strict_types=1);

namespace Web3e\Gateway;

/**
 * Verify an inbound Web3e webhook (IPN) signature.
 *
 * The server delivers (backend gateway-ipn.service.ts + gateway-webhook-sign.ts):
 *   Webhook-Id:        <event id>
 *   Webhook-Signature: v1,t=<unix_s>,s1=<hex>[,s1=<hex_prev>]
 *
 * Canonical signing string:  "v1.{webhookId}.{timestamp}.{rawBody}"
 * Accept when |now - t| <= tolerance AND ANY s1 matches (constant-time). Multiple s1 values occur
 * during a secret rotation window — accepting any one keeps rotation zero-downtime.
 *
 * IMPORTANT: pass the RAW request body bytes (never a re-serialized array) — the signature is over
 * the exact bytes the server POSTed.
 */
final class WebhookVerifier
{
    /** @var string */
    private $secret;
    /** @var int */
    private $tolerance;

    public function __construct(string $secret, int $toleranceSeconds = 300)
    {
        $this->secret = $secret;
        $this->tolerance = $toleranceSeconds;
    }

    public function verify(string $rawBody, string $webhookId, string $signatureHeader): bool
    {
        if ($this->secret === '' || $webhookId === '') {
            return false;
        }
        $parsed = self::parseHeader($signatureHeader);
        if ($parsed === null) {
            return false;
        }
        [$timestamp, $signatures] = $parsed;
        if (abs(time() - $timestamp) > $this->tolerance) {
            return false;
        }

        $expected = hash_hmac('sha256', 'v1.' . $webhookId . '.' . $timestamp . '.' . $rawBody, $this->secret);
        foreach ($signatures as $candidate) {
            if (hash_equals($expected, $candidate)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Parse "v1,t=<ts>,s1=<hex>[,s1=<hex>]" → [timestamp, [s1, ...]], or null if malformed / wrong version.
     *
     * @return array{0:int,1:array<int,string>}|null
     */
    private static function parseHeader(string $header): ?array
    {
        $parts = explode(',', trim($header));
        $version = array_shift($parts);
        if ($version === null || strtolower(trim($version)) !== 'v1') {
            return null;
        }

        $timestamp = null;
        $signatures = [];
        foreach ($parts as $segment) {
            $segment = trim($segment);
            if (strncmp($segment, 't=', 2) === 0) {
                $timestamp = (int) substr($segment, 2);
            } elseif (strncmp($segment, 's1=', 3) === 0) {
                $value = substr($segment, 3);
                if ($value !== '') {
                    $signatures[] = $value;
                }
            }
        }

        if ($timestamp === null || $timestamp <= 0 || $signatures === []) {
            return null;
        }
        return [$timestamp, $signatures];
    }
}
