<?php

namespace App\Security;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Logout\LogoutSuccessHandlerInterface;

final class KeycloakLogoutSuccessHandler implements LogoutSuccessHandlerInterface
{
    public function onLogoutSuccess(Request $request): RedirectResponse
    {
        $base = rtrim((string)($_ENV['KEYCLOAK_AUTH_SERVER_URL'] ?? ''), '/');
        $realm = rawurlencode((string)($_ENV['KEYCLOAK_REALM'] ?? ''));
        $postLogout = (string)($_ENV['APP_LOGOUT_REDIRECT_URL'] ?? '/');

        // If Keycloak env is missing, just go home
        if ($base === '' || $realm === '') {
            return new RedirectResponse($postLogout ?: '/');
        }

        $idToken = null;
        if ($request->hasSession()) {
            $idToken = $request->getSession()->get('kc_id_token');
            $request->getSession()->remove('kc_id_token');
        }

        // Keycloak end-session endpoint
        $url = sprintf('%s/realms/%s/protocol/openid-connect/logout', $base, $realm);

        $qs = [
            'post_logout_redirect_uri' => $postLogout,
        ];
        if (is_string($idToken) && $idToken !== '') {
            $qs['id_token_hint'] = $idToken;
        }

        return new RedirectResponse($url . '?' . http_build_query($qs));
    }
}
