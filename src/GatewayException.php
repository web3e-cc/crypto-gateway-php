<?php

declare(strict_types=1);

namespace Web3e\Gateway;

/**
 * Thrown on any gateway API failure — a transport error, a non-2xx response, or the
 * stable `{ "error": { code, message } }` envelope the v1 API returns on rejection.
 */
class GatewayException extends \RuntimeException
{
    /** @var int HTTP status code (0 when the request never completed). */
    private $httpStatus;

    /** @var string|null Machine-readable gateway error code, e.g. "gateway_api_error_invalid_signature". */
    private $errorCode;

    public function __construct(string $message, int $httpStatus = 0, ?string $errorCode = null)
    {
        parent::__construct($message);
        $this->httpStatus = $httpStatus;
        $this->errorCode = $errorCode;
    }

    public function httpStatus(): int
    {
        return $this->httpStatus;
    }

    public function errorCode(): ?string
    {
        return $this->errorCode;
    }
}
