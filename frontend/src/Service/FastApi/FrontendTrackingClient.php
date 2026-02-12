<?php

namespace App\Service\FastApi;

use App\Service\Security\KeycloakSessionTokenManager;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class FrontendTrackingClient
{
    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly KeycloakSessionTokenManager $tokenManager,
        #[Autowire(service: 'monolog.logger.fastapi')]
        private readonly LoggerInterface $log,
        private readonly string $baseUrl, // FastAPI base URL (same as FastApiClient)
    ) {}

    /**
     * Notes / How to run:
     *  - This is best-effort tracking. It must NEVER throw (so it can't break user requests).
     *  - It calls FastAPI: POST {FASTAPI_BASE_URL}/frontend_tracking/log
     */
    public function log(array $payload, ?string $rid = null): void
    {
        $token = $this->tokenManager->getValidAccessTokenOrNull();
        if (!$token) {
            return; // can't call tracking endpoint without a valid user JWT
        }

        $rid = $rid ?: bin2hex(random_bytes(8));
        $url = rtrim($this->baseUrl, '/') . '/frontend_tracking/log';

        try {
            $this->http->request('POST', $url, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $token,
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                    'X-Request-ID' => $rid,
                ],
                'json' => $payload,
            ])->getContent(false);
        } catch (TransportExceptionInterface $e) {
            $this->log->warning('Frontend tracking log transport error', [
                'rid' => $rid,
                'url' => $url,
                'error' => $e->getMessage(),
            ]);
        } catch (\Throwable $e) {
            $this->log->warning('Frontend tracking log exception', [
                'rid' => $rid,
                'url' => $url,
                'error' => $e->getMessage(),
            ]);
        }
    }
}
