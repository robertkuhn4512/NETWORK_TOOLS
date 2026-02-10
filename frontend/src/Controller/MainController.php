<?php

namespace App\Controller;

use App\Security\KeycloakUser;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

final class MainController extends AbstractController
{
    #[Route('/', name: 'app_home')]
    public function index(#[CurrentUser] ?KeycloakUser $user): Response
    {
        $claims = $user?->claims() ?? [];
        $roles = $user?->getRoles() ?? [];

        return $this->render('main/index.html.twig', [
            'controller_name' => 'MainController',
            'claims' => $claims,
            'roles' => $roles,
        ]);
    }

    #[Route('/admin', name: 'app_admin_portal')]
    public function adminPortal(#[CurrentUser] ?KeycloakUser $user): Response
    {
        $claims = $user?->claims() ?? [];
        $roles = $user?->getRoles() ?? [];

        return $this->render('security/admin.html.twig', [
            'controller_name' => 'MainController',
            'claims' => $claims,
            'roles' => $roles,
        ]);
    }
}
