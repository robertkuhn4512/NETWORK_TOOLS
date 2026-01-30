#!/usr/bin/env sh
set -eu

# Where your internal CA lives (runtime-mounted/generated)
INTERNAL_CA="${INTERNAL_CA_PATH:-/run/certs/networktools_ca.crt}"
COMBINED_CA="${COMBINED_CA_PATH:-/run/certs/combined-ca.crt}"

if [ -f "$INTERNAL_CA" ]; then
  # Prefer certifi bundle if available (httpx often uses certifi)
  CERTIFI_BUNDLE="$(python -c 'import certifi; print(certifi.where())' 2>/dev/null || true)"

  SYS=""
  if [ -n "${CERTIFI_BUNDLE:-}" ] && [ -f "$CERTIFI_BUNDLE" ]; then
    SYS="$CERTIFI_BUNDLE"
  else
    for p in /etc/ssl/certs/ca-certificates.crt /usr/lib/ssl/cert.pem /etc/pki/tls/certs/ca-bundle.crt; do
      [ -f "$p" ] && SYS="$p" && break
    done
  fi

  if [ -z "$SYS" ]; then
    echo "[entrypoint] ERROR: Could not locate a public CA bundle (certifi or system)."
    exit 1
  fi

  echo "[entrypoint] Public CA bundle: $SYS"
  echo "[entrypoint] Internal CA: $INTERNAL_CA"

  # Ensure directory exists (it should, but be safe)
  mkdir -p "$(dirname "$COMBINED_CA")"

  # Build combined bundle (public roots + internal CA)
  cat "$SYS" "$INTERNAL_CA" > "$COMBINED_CA"
  chmod 0644 "$COMBINED_CA"
  echo "[entrypoint] Wrote combined CA bundle: $COMBINED_CA"
else
  echo "[entrypoint] Internal CA not found at $INTERNAL_CA; skipping combined CA bundle."
fi

# If combined bundle exists, advertise it to common TLS consumers.
# This keeps public HTTPS working and also validates internal CA-signed services (Vault).
if [ -f "$COMBINED_CA" ]; then
  export SSL_CERT_FILE="$COMBINED_CA"
  export REQUESTS_CA_BUNDLE="$COMBINED_CA"
  export CURL_CA_BUNDLE="$COMBINED_CA"
  export HTTPX_CA_BUNDLE="$COMBINED_CA"
fi

exec "$@"
