<?php

declare(strict_types=1);

/**
 * Zero-dependency test runner (no PHPUnit needed): `php tests/run.php`.
 * Proves the signing + webhook-verification logic mirrors the server. A live-sandbox integration
 * test is the ultimate proof; this locks the wire format and the verifier's accept/reject rules.
 */

require __DIR__ . '/../src/GatewayException.php';
require __DIR__ . '/../src/Signer.php';
require __DIR__ . '/../src/WebhookVerifier.php';

use Web3e\Gateway\Signer;
use Web3e\Gateway\WebhookVerifier;

$failures = 0;
$count = 0;

function check(string $name, bool $ok): void
{
    global $failures, $count;
    $count++;
    if ($ok) {
        echo "  ok  - {$name}\n";
    } else {
        $failures++;
        echo "  FAIL- {$name}\n";
    }
}

// 1. Empty-body hash equals the canonical SHA-256 of "" (matches the server's SHA256_EMPTY).
check(
    'bodyHash("") == sha256 empty',
    Signer::bodyHash('') === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
);

// 2. Query canonicalization: sort by (key,value), RFC-3986 encode, join with "&".
check(
    'canonicalizeQuery sorts + encodes',
    Signer::canonicalizeQuery('?b=2&a=1&a=0') === 'a=0&a=1&b=2'
);
check(
    'canonicalizeQuery empty -> empty',
    Signer::canonicalizeQuery('') === ''
);
check(
    'canonicalizeQuery encodes spaces as %20',
    Signer::canonicalizeQuery('q=a+b') === 'q=a%20b'
);

// 3. Request signature: exact canonical string + "v1=" prefix, 64 hex chars.
$canonical = Signer::canonicalString('post', '/rest/gateway/api/v1/invoices', 'a=1', '1700000000', 'nonce0123456789ab', '');
$expectedCanonical = "POST\n/rest/gateway/api/v1/invoices\na=1\n1700000000\nnonce0123456789ab\n"
    . 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
check('canonicalString exact shape', $canonical === $expectedCanonical);

$sig = Signer::sign('topsecret', $canonical);
check('sign() has v1= prefix', strpos($sig, 'v1=') === 0);
check('sign() is 64-hex HMAC', (bool) preg_match('/^v1=[0-9a-f]{64}$/', $sig));
check(
    'sign() == known HMAC vector',
    $sig === 'v1=' . hash_hmac('sha256', $canonical, 'topsecret')
);

// 4. Webhook verification (canonical "v1.{id}.{t}.{body}").
$secret = 'whsec_test';
$id = 'evt_123';
$body = '{"orderId":"42","status":"finished"}';
$now = time();
$goodMac = hash_hmac('sha256', 'v1.' . $id . '.' . $now . '.' . $body, $secret);
$verifier = new WebhookVerifier($secret);

check('verify accepts a valid signature', $verifier->verify($body, $id, "v1,t={$now},s1={$goodMac}"));
check('verify rejects a tampered body', !$verifier->verify($body . 'x', $id, "v1,t={$now},s1={$goodMac}"));
check('verify rejects a wrong webhook id', !$verifier->verify($body, 'evt_999', "v1,t={$now},s1={$goodMac}"));
check('verify rejects a stale timestamp', !$verifier->verify($body, $id, 'v1,t=' . ($now - 4000) . ",s1={$goodMac}"));
check('verify rejects a malformed header', !$verifier->verify($body, $id, 'garbage'));
check('verify rejects an empty secret', !(new WebhookVerifier(''))->verify($body, $id, "v1,t={$now},s1={$goodMac}"));

// Rotation: two s1 values (new + previous secret) — accept if EITHER matches.
$prevMac = hash_hmac('sha256', 'v1.' . $id . '.' . $now . '.' . $body, 'whsec_old');
check(
    'verify accepts during rotation (2nd s1)',
    (new WebhookVerifier('whsec_old'))->verify($body, $id, "v1,t={$now},s1={$goodMac},s1={$prevMac}")
);

echo "\n{$count} checks, {$failures} failed\n";
exit($failures === 0 ? 0 : 1);
