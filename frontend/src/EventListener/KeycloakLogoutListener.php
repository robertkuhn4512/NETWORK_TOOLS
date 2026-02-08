<?php

namespace App\EventListener;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Http\Event\LogoutEvent;

#[AsEventListener(event: LogoutEvent::class, dispatcher: 'security.event_dispatcher.main')]
final class KeycloakLogoutListener
{
    public function __construct(
        private readonly string $keycloakAuthServerUrl,   // e.g. https://auth.networkengineertools.com:8443
        private readonly string $keycloakRealm,           // e.g. network_tools
        private readonly string $keycloakClientId,        // e.g. networktools-web
        private readonly string $postLogoutRedirectUri,   // e.g. https://networkengineertools.com:8443/
    ) {}

    public function __invoke(LogoutEvent $event): void
    {
        $request = $event->getRequest();
        $session = $request->hasSession() ? $request->getSession() : null;

        // Optional but recommended (avoids Keycloak logout confirmation in many setups)
        $idToken = null;
        if ($session && $session->isStarted()) {
            $idToken = $session->get('keycloak_id_token');
        }

        $base = rtrim($this->keycloakAuthServerUrl, '/');
        $realm = rawurlencode($this->keycloakRealm);

        $params = [
            'post_logout_redirect_uri' => $this->postLogoutRedirectUri,
            'client_id' => $this->keycloakClientId,
        ];
        if (is_string($idToken) && $idToken !== '') {
            $params['id_token_hint'] = $idToken;
        }

        $logoutUrl = sprintf(
            '%s/realms/%s/protocol/openid-connect/logout?%s',
            $base,
            $realm,
            http_build_query($params, '', '&', PHP_QUERY_RFC3986)
        );

        // now that we've built the redirect, invalidate locally
        if ($session && $session->isStarted()) {
            $session->invalidate();
        }

        $event->setResponse(new RedirectResponse($logoutUrl));
    }
}
