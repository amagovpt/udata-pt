AVATAR_SIZES = [500, 200, 100, 32, 25]
BIGGEST_AVATAR_SIZE = AVATAR_SIZES[0]

# Placeholder email minted on SAML/CMD account creation when the IdP did not
# provide an email (or the CMD email is already taken). Mint and detection
# must always use these constants so they can never drift.
SAML_PLACEHOLDER_EMAIL_PREFIX = "saml-"
SAML_PLACEHOLDER_EMAIL_DOMAIN = "autenticacao.gov.pt"
