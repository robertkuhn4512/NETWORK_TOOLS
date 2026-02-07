<?php

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Http\Event\LogoutEvent;

final class KeycloakLogoutSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [
            LogoutEvent::class => 'onLogout',
        ];
    }

    public function onLogout(LogoutEvent $event): void
    {
        $request = $event->getRequest();

        $base = rtrim((string)($_ENV['KEYCLOAK_AUTH_SERVER_URL'] ?? ''), '/');
        $realm = (string)($_ENV['KEYCLOAK_REALM'] ?? '');
        $postLogout = (string)($_ENV['APP_LOGOUT_REDIRECT_URL'] ?? '/');

        // If Keycloak env isn't set, fall back to the firewall "target"
        if ($base === '' || $realm === '') {
            return;
        }

        // Grab id_token_hint from session if present
        $idToken = null;
        if ($request->hasSession()) {
            $session = $request->getSession();
            $idToken = $session->get('kc_id_token');
            // Now kill the session explicitly (we set invalidate_session:false)
            $session->invalidate();
        }

        $endSessionUrl = sprintf(
            '%s/realms/%s/protocol/openid-connect/logout',
            $base,
            rawurlencode($realm),
        );

        $qs = ['post_logout_redirect_uri' => $postLogout];
        if (is_string($idToken) && $idToken !== '') {
            $qs['id_token_hint'] = $idToken;
        }

        $event->setResponse(new RedirectResponse($endSessionUrl . '?' . http_build_query($qs)));
    }
}
