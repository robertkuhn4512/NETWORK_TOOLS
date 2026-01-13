import os
from dataclasses import dataclass
from typing import List

def _csv(v: str) -> List[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]

@dataclass(frozen=True)
class KeycloakSettings:
    base_url: str
    realm: str
    allowed_azp: List[str]
    verify_audience: bool
    oidc_ca_bundle: str | None

def get_keycloak_settings() -> KeycloakSettings:
    base_url = os.environ["KEYCLOAK_BASE_URL"].rstrip("/")
    realm = os.environ["KEYCLOAK_REALM"]

    allowed_azp = _csv(os.getenv("FASTAPI_ALLOWED_AZP", ""))

    verify_audience = os.getenv("FASTAPI_VERIFY_AUDIENCE", "false").lower() in ("1", "true", "yes")

    oidc_ca_bundle = (
        os.getenv("FASTAPI_OIDC_CA_BUNDLE")
        or os.getenv("SSL_CERT_FILE")
        or None
    )

    return KeycloakSettings(
        base_url=base_url,
        realm=realm,
        allowed_azp=allowed_azp,
        verify_audience=verify_audience,
        oidc_ca_bundle=oidc_ca_bundle,
    )