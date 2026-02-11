<?php

namespace App\Service\Security;

use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class KeycloakSessionTokenManager
{
    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly RequestStack $requestStack,
        private readonly string $tokenUrl,      // {KEYCLOAK_AUTH_SERVER_URL}/realms/{REALM}/protocol/openid-connect/token
        private readonly string $clientId,
        private readonly ?string $clientSecret,
        private readonly int $skewSeconds = 30, // refresh a bit early
    ) {}

    /**
     * Returns a valid access token from session; refreshes if needed.
     * Returns null if user is not logged in / session lacks tokens.
     */
    public function getValidAccessTokenOrNull(): ?string
    {
        $session = $this->requestStack->getSession();
        if (!$session) {
            return null;
        }

        $accessToken = $session->get('kc_access_token');
        $refreshToken = $session->get('kc_refresh_token');
        $expiresAt = (int) $session->get('kc_access_expires_at', 0);

        if (!is_string($accessToken) || $accessToken === '') {
            return null;
        }

        // Still valid (with skew)
        if ($expiresAt > (time() + $this->skewSeconds)) {
            return $accessToken;
        }

        // Can't refresh
        if (!is_string($refreshToken) || $refreshToken === '') {
            return null;
        }

        // Refresh token request
        $body = [
            'grant_type' => 'refresh_token',
            'client_id' => $this->clientId,
            'refresh_token' => $refreshToken,
        ];
        if (is_string($this->clientSecret) && $this->clientSecret !== '') {
            $body['client_secret'] = $this->clientSecret;
        }

        $resp = $this->http->request('POST', $this->tokenUrl, [
            'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'],
            'body' => $body,
        ]);

        $data = $resp->toArray(false);

        if (empty($data['access_token'])) {
            return null;
        }

        $session->set('kc_access_token', (string)$data['access_token']);

        // Keycloak may rotate refresh tokens
        if (!empty($data['refresh_token'])) {
            $session->set('kc_refresh_token', (string)$data['refresh_token']);
        }

        $expiresIn = (int)($data['expires_in'] ?? 60);
        $session->set('kc_access_expires_at', time() + max(10, $expiresIn));

        return (string)$data['access_token'];
    }
}
