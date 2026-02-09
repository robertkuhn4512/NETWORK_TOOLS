<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Http\Event\LogoutEvent;

#[AsEventListener(event: LogoutEvent::class, dispatcher: 'security.event_dispatcher.main')]
final class KeycloakLogoutListener
{
    public function __construct(
        private readonly string $keycloakAuthServerUrl,
        private readonly string $keycloakRealm,
        private readonly string $keycloakClientId,
        private readonly string $postLogoutRedirectUri,
    ) {}

    public function __invoke(LogoutEvent $event): void
    {
        $request = $event->getRequest();

        // Always default to a safe local redirect
        $fallback = new RedirectResponse($this->postLogoutRedirectUri ?: '/');

        if (!$request->hasSession()) {
            $event->setResponse($fallback);
            return;
        }

        $session = $request->getSession();

        // Try both keys (your authenticator stores both)
        $idToken = $session->get('kc_id_token') ?: $session->get('keycloak_id_token');

        // Clear session regardless
        $session->remove('kc_id_token');
        $session->remove('keycloak_id_token');

        // If we don't have an ID token, don't call Keycloak end-session (it will error)
        if (!is_string($idToken) || $idToken === '') {
            $session->invalidate();
            $event->setResponse($fallback);
            return;
        }

        $base = rtrim($this->keycloakAuthServerUrl, '/');
        $realm = rawurlencode($this->keycloakRealm);

        $url = sprintf('%s/realms/%s/protocol/openid-connect/logout', $base, $realm);

        $qs = [
            'client_id' => $this->keycloakClientId,
            'post_logout_redirect_uri' => $this->postLogoutRedirectUri,
            'id_token_hint' => $idToken,
        ];

        $session->invalidate();
        $event->setResponse(new RedirectResponse($url.'?'.http_build_query($qs)));
    }
}
