<?php

namespace App\Security;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

final class KeycloakAuthenticator extends OAuth2Authenticator implements AuthenticationEntryPointInterface
{
    use TargetPathTrait;

    private const FIREWALL_NAME = 'main';

    private function decodeJwtPayload(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) < 2) {
            return [];
        }

        $payload = $parts[1];

        // base64url -> base64 (+ padding)
        $payload = strtr($payload, '-_', '+/');
        $pad = strlen($payload) % 4;
        if ($pad !== 0) {
            $payload .= str_repeat('=', 4 - $pad);
        }

        $json = base64_decode($payload, true);
        if ($json === false) {
            return [];
        }

        $data = json_decode($json, true);
        return is_array($data) ? $data : [];
    }

    private function extractRolesFromTokenPayload(array $p): array
    {
        $roles = [];

        if (isset($p['realm_access']['roles']) && is_array($p['realm_access']['roles'])) {
            $roles = array_merge($roles, $p['realm_access']['roles']);
        }

        $clientId = getenv('KEYCLOAK_CLIENT_ID') ?: ($_ENV['KEYCLOAK_CLIENT_ID'] ?? null);
        if ($clientId && isset($p['resource_access'][$clientId]['roles']) && is_array($p['resource_access'][$clientId]['roles'])) {
            $roles = array_merge($roles, $p['resource_access'][$clientId]['roles']);
        }

        // Normalize to ROLE_*
        $roles = array_values(array_unique(array_map(
            static fn($r) => (is_string($r) && str_starts_with($r, 'ROLE_')) ? $r : ('ROLE_' . strtoupper((string)$r)),
            $roles
        )));

        return $roles;
    }

    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly UrlGeneratorInterface $urls,
        private readonly KeycloakUserProvider $userProvider,
    ) {}

    public function supports(Request $request): ?bool
    {
        return $request->attributes->get('_route') === 'connect_keycloak_check';
    }

    /**
     * Entry point: called when an anonymous user hits a protected page.
     */
    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        // Save where they were trying to go, so we can send them back after login
        if ($request->hasSession() && $request->isMethod('GET')) {
            $this->saveTargetPath($request->getSession(), self::FIREWALL_NAME, $request->getUri());
        }

        // Kick off OAuth flow (your controller route that does $client->redirect(...))
        return new RedirectResponse($this->urls->generate('connect_keycloak_start'));
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $client = $this->clients->getClient('keycloak');

        /** @var AccessToken $accessToken */
        $accessToken = $this->fetchAccessToken($client);

        // Decode JWT payload (roles live here)
        $accessPayload = $this->decodeJwtPayload($accessToken->getToken());
        $roles = $this->extractRolesFromTokenPayload($accessPayload);

        // Keep userinfo for nice profile fields
        $resourceOwner = $client->fetchUserFromToken($accessToken);
        $userinfo = $resourceOwner->toArray();

        // Store id_token for logout if available
        $values = method_exists($accessToken, 'getValues') ? $accessToken->getValues() : [];
        $idToken = $values['id_token'] ?? null;
        if ($request->hasSession() && is_string($idToken) && $idToken !== '') {
            $request->getSession()->set('keycloak_id_token', $idToken);
            $request->getSession()->set('kc_id_token', $idToken);
        }

        // Pick identifier from token first, then userinfo
        $userIdentifier =
            $accessPayload['preferred_username']
            ?? $userinfo['preferred_username']
            ?? $accessPayload['email']
            ?? $userinfo['email']
            ?? null;

        if (!$userIdentifier) {
            throw new AuthenticationException('Keycloak did not return preferred_username or email.');
        }

        // Merge what you want to inspect (dev-friendly)
        $claims = array_merge($userinfo, [
            '__access_token' => $accessPayload, // remove later if you want
        ]);

        return new SelfValidatingPassport(
            new UserBadge($userIdentifier, function () use ($userIdentifier, $claims, $roles) {
                return $this->userProvider->loadOrCreateFromKeycloak($userIdentifier, $claims, $roles);
            })
        );
    }


    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?RedirectResponse
    {
        if ($request->hasSession()) {
            $target = $this->getTargetPath($request->getSession(), self::FIREWALL_NAME);
            if ($target) {
                return new RedirectResponse($target);
            }
        }

        return new RedirectResponse($this->urls->generate('app_home'));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?RedirectResponse
    {
        return new RedirectResponse($this->urls->generate('app_login'));
    }
}
