<?php

namespace App\Service\FastApi;

use App\Service\Security\KeycloakSessionTokenManager;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\DecodingExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class FastApiClient
{
    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly KeycloakSessionTokenManager $tokenManager,
        private readonly string $baseUrl,
    ) {}

    /**
     * Fetch initial devices datatable payload from FastAPI.
     *
     * @return array{
     *   status:int,
     *   ok:bool,
     *   data:mixed,
     *   error: array{
     *     type:string,
     *     message:string,
     *     status?:int,
     *     upstream?:mixed,
     *     raw?:string
     *   }|null
     * }
     */
    public function fetchDevicesDatatableInitial(int $limit = 10): array
    {
        $limit = ($limit > 0) ? $limit : 10;

        $accessToken = $this->tokenManager->getValidAccessTokenOrNull();
        if (!$accessToken) {
            return [
                'status' => 401,
                'ok' => false,
                'data' => null,
                'error' => [
                    'type' => 'auth',
                    'message' => 'Not authenticated (no valid Keycloak access token in session).',
                    'status' => 401,
                ],
            ];
        }

        $url = rtrim($this->baseUrl, '/') . '/device_reporting/datatable/devices';

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

            // IMPORTANT: use getContent(false) so 4xx/5xx doesn't throw.
            $status = $resp->getStatusCode();
            $raw = $resp->getContent(false);

            $decoded = null;
            $isJson = false;

            // Best-effort JSON decode
            if ($raw !== '') {
                $decoded = json_decode($raw, true);
                $isJson = (json_last_error() === JSON_ERROR_NONE);
            }

            if ($status >= 200 && $status < 300) {
                return [
                    'status' => $status,
                    'ok' => true,
                    'data' => $isJson ? $decoded : $raw,
                    'error' => null,
                ];
            }

            // Build richer error messages by status range
            $type = 'http_error';
            $message = 'FastAPI returned an error response.';

            if ($status === 401 || $status === 403) {
                $type = 'auth';
                $message = 'FastAPI rejected the request (auth/permissions).';
            } elseif ($status === 404) {
                $type = 'not_found';
                $message = 'FastAPI endpoint not found (check base URL / path).';
            } elseif ($status >= 500 && $status <= 599) {
                $type = 'upstream';
                // Common reverse-proxy/upstream failures
                if ($status === 502) {
                    $message = 'Bad gateway (proxy/upstream failure reaching FastAPI).';
                } elseif ($status === 503) {
                    $message = 'Service unavailable (FastAPI overloaded or restarting).';
                } elseif ($status === 504) {
                    $message = 'Gateway timeout (FastAPI took too long to respond).';
                } else {
                    $message = 'FastAPI internal/server error.';
                }
            } elseif ($status >= 400 && $status <= 499) {
                $type = 'client_error';
                $message = 'Request rejected by FastAPI (validation/client error).';
            }

            // Prefer structured upstream error if JSON
            $upstream = $isJson ? $decoded : null;

            return [
                'status' => $status,
                'ok' => false,
                'data' => $upstream ?? $raw, // keep raw for debugging if not JSON
                'error' => [
                    'type' => $type,
                    'message' => $message,
                    'status' => $status,
                    'upstream' => $upstream,
                    // include raw only if not JSON (so we don't duplicate large payloads)
                    'raw' => $isJson ? null : $raw,
                ],
            ];

        } catch (TransportExceptionInterface $e) {
            // DNS failures, connection refused, timeouts, TLS failures, etc.
            return [
                'status' => 502,
                'ok' => false,
                'data' => null,
                'error' => [
                    'type' => 'transport',
                    'message' => 'FastAPI request failed (transport error).',
                    'status' => 502,
                    'raw' => $e->getMessage(),
                ],
            ];
        } catch (\Throwable $e) {
            // Catch-all for anything unexpected on the PHP side
            return [
                'status' => 500,
                'ok' => false,
                'data' => null,
                'error' => [
                    'type' => 'php_exception',
                    'message' => 'Unexpected client-side error while calling FastAPI.',
                    'status' => 500,
                    'raw' => $e->getMessage(),
                ],
            ];
        }
    }
}
