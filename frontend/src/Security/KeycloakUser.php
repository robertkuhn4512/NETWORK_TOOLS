<?php

namespace App\Security;

use Symfony\Component\Security\Core\User\UserInterface;

final class KeycloakUser implements UserInterface
{
    public function __construct(
        private readonly string $userIdentifier,
        private readonly array $roles = [],
        private readonly array $claims = [],
    ) {}

    public function getUserIdentifier(): string
    {
        return $this->userIdentifier;
    }

    public function getRoles(): array
    {
        return array_values(array_unique(array_merge(['ROLE_USER'], $this->roles)));
    }

    public function eraseCredentials(): void {}

    public function claims(): array
    {
        return $this->claims;
    }
}
