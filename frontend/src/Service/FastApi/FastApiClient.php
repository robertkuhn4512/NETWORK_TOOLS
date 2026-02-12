<?php

namespace App\Service\FastApi;

use App\Service\Security\KeycloakSessionTokenManager;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class FastApiClient
{
    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly KeycloakSessionTokenManager $tokenManager,
        #[Autowire(service: 'monolog.logger.fastapi')]
        private readonly LoggerInterface $log,
        private readonly string $baseUrl,

        // NEW: injected tracking client (best-effort)
        private readonly ?FrontendTrackingClient $tracking = null,

        // NEW: lets us derive the current Symfony route/path automatically
        private readonly RequestStack $requestStack = new RequestStack(),
    ) {}

    public function fetchDevicesDatatable(array $datatablePayload, ?string $requestId = null): array
    {
        $requestId = $requestId ?: bin2hex(random_bytes(8));

        $accessToken = $this->tokenManager->getValidAccessTokenOrNull();
        if (!$accessToken) {
            $this->log->warning('FastAPI call blocked: no Keycloak token', [
                'rid' => $requestId,
                'endpoint' => 'device_reporting/datatable/devices',
            ]);

            $this->track(
                rid: $requestId,
                event: 'fastapi_call.blocked',
                level: 'warning',
                message: 'FastAPI call blocked (no user token)',
                context: [
                    'fastapi_endpoint' => '/device_reporting/datatable/devices',
                    'fastapi_method' => 'POST',
                    'client_method' => __FUNCTION__,
                    'status' => 401,
                ],
            );

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

        $path = '/device_reporting/datatable/devices';
        $url = rtrim($this->baseUrl, '/') . $path;

        // Normalize minimum fields (keeps FastAPI happy if something is missing)
        $datatablePayload['draw'] = (int)($datatablePayload['draw'] ?? 1);
        $datatablePayload['start'] = max(0, (int)($datatablePayload['start'] ?? 0));
        $datatablePayload['length'] = max(1, (int)($datatablePayload['length'] ?? 25));
        $datatablePayload['search'] = $datatablePayload['search'] ?? ['value' => '', 'regex' => false];
        $datatablePayload['order'] = $datatablePayload['order'] ?? [['column' => 0, 'dir' => 'asc']];
        $datatablePayload['columns'] = $datatablePayload['columns'] ?? [];

        $headers = [
            'Authorization' => 'Bearer ' . $accessToken,
            'Accept' => 'application/json',
            'X-Request-ID' => $requestId,
        ];

        $t0 = microtime(true);

        $this->log->info('FastAPI request', [
            'rid' => $requestId,
            'method' => 'POST',
            'url' => $url,
            'headers' => $this->redactHeaders($headers),
            'payload_meta' => [
                'draw' => $datatablePayload['draw'],
                'start' => $datatablePayload['start'],
                'length' => $datatablePayload['length'],
                'search' => is_array($datatablePayload['search']) ? ($datatablePayload['search']['value'] ?? '') : '',
            ],
        ]);

        try {
            $resp = $this->http->request('POST', $url, [
                'headers' => $headers,
                'json' => $datatablePayload,
            ]);

            $status = $resp->getStatusCode();
            $raw = (string)$resp->getContent(false);
            $respHeaders = $resp->getHeaders(false);
            $contentType = $respHeaders['content-type'][0] ?? null;

            $ms = (int) round((microtime(true) - $t0) * 1000);
            $norm = $this->normalizeUpstreamBody($raw, $contentType);

            if ($status >= 200 && $status < 300) {
                $this->track(
                    rid: $requestId,
                    event: 'fastapi_call.success',
                    level: 'info',
                    message: 'FastAPI request ok',
                    context: [
                        'client_method' => __FUNCTION__,
                        'fastapi_method' => 'POST',
                        'fastapi_endpoint' => $path,
                        'status' => $status,
                        'duration_ms' => $ms,
                    ],
                );

                return [
                    'status' => $status,
                    'ok' => true,
                    'data' => ($norm['kind'] === 'json') ? $norm['json'] : $raw,
                    'error' => null,
                ];
            }

            $type = ($status === 401 || $status === 403) ? 'auth' : (($status >= 500) ? 'upstream' : 'client_error');
            $message = ($status >= 500) ? 'FastAPI server error.' : 'FastAPI rejected the request.';

            $this->track(
                rid: $requestId,
                event: 'fastapi_call.failed',
                level: 'error',
                message: $message,
                context: [
                    'client_method' => __FUNCTION__,
                    'fastapi_method' => 'POST',
                    'fastapi_endpoint' => $path,
                    'status' => $status,
                    'duration_ms' => $ms,
                    'error_type' => $type,
                    'upstream_preview' => $this->previewForLog($norm),
                ],
            );

            return [
                'status' => $status,
                'ok' => false,
                'data' => null,
                'error' => [
                    'type' => $type,
                    'message' => $message,
                    'status' => $status,
                    'upstream' => ($norm['kind'] === 'json') ? $norm['json'] : null,
                    'preview' => $this->previewForLog($norm),
                ],
            ];

        } catch (TransportExceptionInterface $e) {
            $ms = (int) round((microtime(true) - $t0) * 1000);

            $this->track(
                rid: $requestId,
                event: 'fastapi_call.transport_error',
                level: 'error',
                message: 'FastAPI request failed (transport error).',
                context: [
                    'client_method' => __FUNCTION__,
                    'fastapi_method' => 'POST',
                    'fastapi_endpoint' => $path,
                    'status' => 502,
                    'duration_ms' => $ms,
                    'error' => $this->collapseWhitespace($e->getMessage(), 600),
                ],
            );

            return [
                'status' => 502,
                'ok' => false,
                'data' => null,
                'error' => [
                    'type' => 'transport',
                    'message' => 'FastAPI request failed (transport error).',
                    'status' => 502,
                    'preview' => [
                        'kind' => 'text',
                        'content_type' => null,
                        'title' => 'Transport error',
                        'snippet' => $this->collapseWhitespace($e->getMessage(), 300),
                    ],
                ],
            ];
        } catch (\Throwable $e) {
            $this->track(
                rid: $requestId,
                event: 'fastapi_call.client_exception',
                level: 'error',
                message: 'Unexpected client-side error while calling FastAPI.',
                context: [
                    'client_method' => __FUNCTION__,
                    'fastapi_method' => 'POST',
                    'fastapi_endpoint' => $path,
                    'status' => 500,
                    'error' => $this->collapseWhitespace($e->getMessage(), 600),
                ],
            );

            return [
                'status' => 500,
                'ok' => false,
                'data' => null,
                'error' => [
                    'type' => 'php_exception',
                    'message' => 'Unexpected client-side error while calling FastAPI.',
                    'status' => 500,
                    'preview' => [
                        'kind' => 'text',
                        'content_type' => null,
                        'title' => 'PHP exception',
                        'snippet' => $this->collapseWhitespace($e->getMessage(), 300),
                    ],
                ],
            ];
        }
    }


    /**
     * Sends a tracking event if tracking is enabled.
     * This must NEVER throw.
     */
    private function track(string $rid, string $event, string $level, string $message, array $context = []): void
    {
        if (!$this->tracking) {
            return;
        }

        try {
            $req = $this->requestStack->getCurrentRequest();

            $payload = [
                'route' => $req?->getPathInfo() ?? '(no_request)',
                'event' => $event,
                'level' => $level,
                'message' => $message,
                'context' => array_merge([
                    'symfony_route_name' => $req?->attributes->get('_route'),
                    'rid' => $rid,
                ], $context),
            ];

            $this->tracking->log($payload, $rid);
        } catch (\Throwable) {
            // never break the main request
        }
    }

    private function redactHeaders(array $headers): array
    {
        $out = $headers;

        foreach (['Authorization', 'Cookie'] as $k) {
            if (isset($out[$k])) {
                $out[$k] = '[REDACTED]';
            }
        }

        return $out;
    }

    /**
     * @return array{
     *   kind:'json'|'html'|'text'|'empty',
     *   content_type?:string|null,
     *   title?:string|null,
     *   snippet?:string|null,
     *   json?:mixed
     * }
     */
    private function normalizeUpstreamBody(string $raw, ?string $contentType): array
    {
        $raw = (string)$raw;

        if ($raw === '') {
            return ['kind' => 'empty', 'content_type' => $contentType];
        }

        $ct = $contentType ? strtolower($contentType) : '';
        $trim = ltrim($raw);

        $looksJson = str_contains($ct, 'application/json') || ($trim !== '' && ($trim[0] === '{' || $trim[0] === '['));
        if ($looksJson) {
            $decoded = json_decode($raw, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                return [
                    'kind' => 'json',
                    'content_type' => $contentType,
                    'json' => $decoded,
                ];
            }
        }

        $looksHtml =
            str_contains($ct, 'text/html')
            || stripos($raw, '<html') !== false
            || preg_match('/^\s*<!doctype\s+html/i', $raw) === 1;

        if ($looksHtml) {
            $title = $this->extractTagText($raw, 'title') ?? $this->extractTagText($raw, 'h1');
            $snippet = $this->collapseWhitespace(html_entity_decode(strip_tags($raw), ENT_QUOTES | ENT_HTML5), 600);

            return [
                'kind' => 'html',
                'content_type' => $contentType,
                'title' => $title ? $this->collapseWhitespace($title, 120) : null,
                'snippet' => $snippet,
            ];
        }

        return [
            'kind' => 'text',
            'content_type' => $contentType,
            'title' => null,
            'snippet' => $this->collapseWhitespace($raw, 600),
        ];
    }

    private function previewForLog(array $norm): array
    {
        return [
            'kind' => $norm['kind'] ?? 'text',
            'content_type' => $norm['content_type'] ?? null,
            'title' => $norm['title'] ?? null,
            'snippet' => $norm['snippet'] ?? null,
        ];
    }

    private function extractTagText(string $html, string $tag): ?string
    {
        $tag = preg_quote($tag, '/');
        if (preg_match('/<'.$tag.'\b[^>]*>(.*?)<\/'.$tag.'>/is', $html, $m)) {
            $txt = trim((string)$m[1]);
            return $txt !== '' ? $txt : null;
        }
        return null;
    }

    private function collapseWhitespace(string $s, int $maxLen): string
    {
        $s = preg_replace('/\s+/u', ' ', trim($s)) ?? trim($s);
        if (mb_strlen($s) > $maxLen) {
            return mb_substr($s, 0, $maxLen) . '…';
        }
        return $s;
    }
}
