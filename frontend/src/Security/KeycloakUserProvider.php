<?php

namespace App\Security;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

final class KeycloakUserProvider implements UserProviderInterface
{
    public function refreshUser(UserInterface $user): UserInterface
    {
        return $user;
    }

    public function supportsClass(string $class): bool
    {
        return $class === KeycloakUser::class;
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        // session reload (no DB yet)
        return new KeycloakUser($identifier);
    }

    public function loadOrCreateFromKeycloak(string $identifier, array $claims, array $roles): KeycloakUser
    {
        return new KeycloakUser($identifier, $roles, $claims);
    }
}
