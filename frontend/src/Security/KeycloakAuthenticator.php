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

        $values = method_exists($accessToken, 'getValues') ? $accessToken->getValues() : [];
        $idToken = $values['id_token'] ?? null;

        if ($request->hasSession() && is_string($idToken) && $idToken !== '') {
            // Store under BOTH keys for compatibility with whatever your logout code reads
            $request->getSession()->set('keycloak_id_token', $idToken);
            $request->getSession()->set('kc_id_token', $idToken);
        }

        $resourceOwner = $client->fetchUserFromToken($accessToken);
        $data = $resourceOwner->toArray();

        $userIdentifier = $data['preferred_username'] ?? $data['email'] ?? null;
        if (!$userIdentifier) {
            throw new AuthenticationException('Keycloak did not return preferred_username or email.');
        }

        $roles = [];
        if (isset($data['realm_access']['roles']) && is_array($data['realm_access']['roles'])) {
            $roles = array_merge($roles, $data['realm_access']['roles']);
        }

        $clientId = $_ENV['KEYCLOAK_CLIENT_ID'] ?? null;
        if ($clientId && isset($data['resource_access'][$clientId]['roles']) && is_array($data['resource_access'][$clientId]['roles'])) {
            $roles = array_merge($roles, $data['resource_access'][$clientId]['roles']);
        }

        $roles = array_values(array_unique(array_map(
            static fn(string $r) => str_starts_with($r, 'ROLE_') ? $r : 'ROLE_' . strtoupper($r),
            $roles
        )));

        return new SelfValidatingPassport(
            new UserBadge($userIdentifier, function () use ($userIdentifier, $data, $roles) {
                return $this->userProvider->loadOrCreateFromKeycloak($userIdentifier, $data, $roles);
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
