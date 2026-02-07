<?php

use Symfony\Component\Dotenv\Dotenv;

require dirname(__DIR__).'/vendor/autoload.php';

$dotenv = new Dotenv();
$dotenv->usePutenv(true);

/**
 * Load Vault-rendered env FIRST so APP_ENV/APP_DEBUG are correct before bootEnv().
 * Then bootEnv loads .env defaults WITHOUT overwriting real env (Vault wins).
 */
$vaultEnv = $_SERVER['VAULT_SECRETS_ENV']
    ?? $_ENV['VAULT_SECRETS_ENV']
    ?? getenv('VAULT_SECRETS_ENV')
    ?? '/run/vault/frontend.env';

if (is_string($vaultEnv) && $vaultEnv !== '' && is_readable($vaultEnv)) {
    $dotenv->overload($vaultEnv);
}

$dotenv->bootEnv(dirname(__DIR__).'/.env');
