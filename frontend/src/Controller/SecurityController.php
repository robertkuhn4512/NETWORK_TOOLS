<?php

namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class SecurityController extends AbstractController
{
    #[Route('/login', name: 'app_login', methods: ['GET'])]
    public function login(): Response
    {
        return $this->redirectToRoute('connect_keycloak_start');
    }

    #[Route('/connect/keycloak', name: 'connect_keycloak_start', methods: ['GET'])]
    public function connectKeycloakStart(ClientRegistry $clientRegistry): Response
    {
        return $clientRegistry
            ->getClient('keycloak')
            ->redirect(['openid', 'profile', 'email']);
    }

    #[Route('/connect/keycloak/check', name: 'connect_keycloak_check', methods: ['GET'])]
    public function connectKeycloakCheck(): Response
    {
        // Handled by the authenticator. You can keep this for completeness.
        return $this->redirectToRoute('app_home');
    }

    #[Route('/logout', name: 'app_logout', methods: ['POST'])]
    public function logout(): void
    {
        throw new \LogicException('This route is intercepted by the firewall logout.');
    }
}
