<?php

namespace App\Service\FastApi;

use App\Service\Security\KeycloakSessionTokenManager;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class FastApiClient
{
    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly KeycloakSessionTokenManager $tokenManager,
        private readonly string $baseUrl, // injected via services.yaml fastapi.base_url
    ) {}

    /**
     * Fetch initial devices datatable payload from FastAPI.
     *
     * @return array{status:int, data:mixed}
     */
    public function fetchDevicesDatatableInitial(int $limit = 10): array
    {
        $limit = ($limit > 0) ? $limit : 10;

        $accessToken = $this->tokenManager->getValidAccessTokenOrNull();
        if (!$accessToken) {
            return [
                'status' => 401,
                'data' => ['detail' => 'Not authenticated (no valid Keycloak access token in session).'],
            ];
        }

        $url = rtrim($this->baseUrl, '/') . '/device_reporting/datatable/devices';

        // Default payload (only "length" is overridden by $limit)
        $payload = [
            'draw' => 1,
            'start' => 0,
            'length' => $limit,
            'search' => ['value' => '', 'regex' => false],
            'order' => [
                ['column' => 0, 'dir' => 'asc'],
            ],
            'columns' => [
                ['data' => 'id', 'name' => '', 'searchable' => true, 'orderable' => true, 'search' => ['value' => '', 'regex' => false]],
                ['data' => 'product_id', 'name' => '', 'searchable' => true, 'orderable' => true, 'search' => ['value' => '', 'regex' => false]],
                ['data' => 'product_id_description', 'name' => '', 'searchable' => true, 'orderable' => true, 'search' => ['value' => '', 'regex' => false]],
                ['data' => 'last_date_of_support', 'name' => '', 'searchable' => true, 'orderable' => true, 'search' => ['value' => '', 'regex' => false]],
                ['data' => 'datetimestamp', 'name' => '', 'searchable' => true, 'orderable' => true, 'search' => ['value' => '', 'regex' => false]],
            ],
        ];

        try {
            $resp = $this->http->request('POST', $url, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $accessToken,
                    'Accept' => 'application/json',
                ],
                'json' => $payload,
            ]);

            $status = $resp->getStatusCode();

            // toArray(false) prevents exceptions for non-2xx
            $data = $resp->toArray(false);

            return ['status' => $status, 'data' => $data];
        } catch (TransportExceptionInterface $e) {
            return [
                'status' => 502,
                'data' => ['detail' => 'FastAPI request failed (transport error).', 'error' => $e->getMessage()],
            ];
        }
    }
}
