#!/bin/sh
set -e

CREDS_DIR="/app/udata/auth/saml/credentials"
PRIVATE_KEY="$CREDS_DIR/private.pem"
PUBLIC_CERT="$CREDS_DIR/public.pem"

if [ ! -f "$PRIVATE_KEY" ]; then
    if [ "${SAML_GENERATE_SELF_SIGNED:-false}" = "true" ]; then
        echo "[entrypoint] SAML credentials not found. Generating self-signed certificate for development..."
        mkdir -p "$CREDS_DIR"
        openssl req -x509 -newkey rsa:4096 -keyout "$PRIVATE_KEY" -out "$PUBLIC_CERT" \
            -days 365 -nodes \
            -subj "/C=PT/ST=Lisboa/L=Lisboa/O=Dev/CN=udata-saml-dev"
        echo "[entrypoint] Self-signed SAML certificate generated."
    else
        echo "[entrypoint] ERROR: SAML private key not found at $PRIVATE_KEY"
        echo "[entrypoint] Mount the credentials volume or set SAML_GENERATE_SELF_SIGNED=true for development."
        exit 1
    fi
fi

exec "$@"
