<p align="center">
  <img src="https://raw.githubusercontent.com/web3e-cc/crypto-gateway-php/main/art/logo.png" width="96" alt="Web3e" />
</p>

# web3e/crypto-gateway-php

PHP SDK for the **Web3e** crypto payment gateway. Zero runtime dependencies (just `ext-curl` +
`ext-hash`), PHP 7.4+, so it drops into any host — including plugins that vendor it into a zip.

It does two things:

1. **Signs requests** to the public REST v1 API (v2 signing scheme: HMAC-SHA256 over
   `METHOD\nPATH\nQUERY\nTIMESTAMP\nNONCE\nSHA256(body)`, single-use nonce, `Idempotency-Key` on POST).
2. **Verifies inbound webhooks** (`SM-Webhook-Signature: v1,t=…,s1=…`, canonical `v1.{id}.{ts}.{body}`,
   ±300s window, constant-time, rotation-aware).

## Install

```bash
composer require web3e/crypto-gateway-php
```

> If the `web3e` vendor is already taken on Packagist, we publish as `web3e-cc/crypto-gateway-php`.

## Accept a payment (hosted checkout)

```php
use Web3e\Gateway\Client;

$client = new Client('gwk_public_id', 'api_secret', 'https://api.web3e.cc');

$invoice = $client->createInvoice([
    'order_id'       => '1001',
    'order_amount'   => '49.90',
    'order_currency' => 'USD',
    'success_url'    => 'https://shop.example/thank-you',
    'cancel_url'     => 'https://shop.example/cart',
    'callback_url'   => 'https://shop.example/ipn/web3e',
]);

header('Location: ' . $invoice['checkout_url']); // redirect the buyer
```

## Verify a webhook (IPN)

```php
use Web3e\Gateway\WebhookVerifier;

$raw       = file_get_contents('php://input');
$webhookId = $_SERVER['HTTP_WEBHOOK_ID'] ?? '';
$signature = $_SERVER['HTTP_WEBHOOK_SIGNATURE'] ?? '';

$verifier = new WebhookVerifier('your_webhook_secret');
if (!$verifier->verify($raw, $webhookId, $signature)) {
    http_response_code(401);
    exit;
}
$event = json_decode($raw, true);
// mark $event['order_id'] paid when $event['status'] is finished/confirmed
```

## Test

```bash
php tests/run.php     # zero-dependency; no composer install required
```

## License

MIT — see [LICENSE](LICENSE).
