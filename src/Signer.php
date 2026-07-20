<?php

declare(strict_types=1);

namespace Web3e\Gateway;

/**
 * Request signing for the Web3e public REST v1 API (scheme "v2").
 *
 * The canonical string MUST match the server byte-for-byte (backend
 * gateway-signature.service.ts):
 *
 *   canonical = METHOD "\n" PATH "\n" CANONICAL_QUERY "\n" TIMESTAMP "\n" NONCE "\n" SHA256_HEX(rawBody)
 *   SM-Signature = "v1=" . hex( HMAC-SHA256(secret, canonical) )
 *
 * Headers the server expects (universal SM- prefix): SM-Api-Key (public id), SM-Timestamp (unix seconds),
 * SM-Nonce (>= 16 chars, single-use), SM-Signature ("v1=<hex>"). (Legacy X-* still works server-side during
 * the migration window; SM- is canonical.)
 */
final class Signer
{
    public const VERSION = 'v1';

    /** @var string */
    private $secret;

    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    /**
     * Build the four signed headers for a request.
     *
     * @param string $query the RAW query string (without a leading "?"), exactly as it goes on the wire
     * @return array<string,string>
     */
    public function headers(string $publicId, string $method, string $path, string $query, string $rawBody): array
    {
        $timestamp = (string) time();
        $nonce = self::nonce();
        $canonical = self::canonicalString($method, $path, $query, $timestamp, $nonce, $rawBody);

        return [
            'SM-Api-Key' => $publicId,
            'SM-Timestamp' => $timestamp,
            'SM-Nonce' => $nonce,
            'SM-Signature' => self::sign($this->secret, $canonical),
        ];
    }

    public static function sign(string $secret, string $canonical): string
    {
        return self::VERSION . '=' . hash_hmac('sha256', $canonical, $secret);
    }

    public static function canonicalString(
        string $method,
        string $path,
        string $query,
        string $timestamp,
        string $nonce,
        string $rawBody
    ): string {
        return implode("\n", [
            strtoupper($method),
            $path,
            self::canonicalizeQuery($query),
            $timestamp,
            $nonce,
            self::bodyHash($rawBody),
        ]);
    }

    /** SHA-256 hex of the raw body bytes (the empty-string hash when there is no body). */
    public static function bodyHash(string $rawBody): string
    {
        return hash('sha256', $rawBody);
    }

    /**
     * Canonicalize a query string: decode -> sort by (key, value) -> RFC-3986 re-encode -> join with "&".
     * Empty string when there are no params. rawurlencode() in PHP already follows RFC-3986 (encodes
     * everything except A-Za-z0-9-_.~), matching the server's rfc3986() helper. Sorting is a byte compare
     * (strcmp), which agrees with the server for the ASCII query params this API uses.
     */
    public static function canonicalizeQuery(string $query): string
    {
        $query = ltrim($query, '?');
        if ($query === '') {
            return '';
        }

        $pairs = [];
        foreach (explode('&', $query) as $part) {
            if ($part === '') {
                continue;
            }
            $eq = strpos($part, '=');
            if ($eq === false) {
                $pairs[] = [self::decode($part), ''];
            } else {
                $pairs[] = [self::decode(substr($part, 0, $eq)), self::decode(substr($part, $eq + 1))];
            }
        }

        usort($pairs, static function (array $a, array $b): int {
            return $a[0] === $b[0] ? strcmp($a[1], $b[1]) : strcmp($a[0], $b[0]);
        });

        $out = [];
        foreach ($pairs as $pair) {
            $out[] = rawurlencode($pair[0]) . '=' . rawurlencode($pair[1]);
        }

        return implode('&', $out);
    }

    /** Decode a percent-encoded component, treating "+" as a space (matches the server's decodeSafe). */
    private static function decode(string $value): string
    {
        return urldecode($value);
    }

    /** A single-use nonce: 32 hex chars (well above the server's 16-char minimum). */
    public static function nonce(): string
    {
        return bin2hex(random_bytes(16));
    }
}
