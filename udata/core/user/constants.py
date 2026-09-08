AVATAR_SIZES = [500, 200, 100, 32, 25]
BIGGEST_AVATAR_SIZE = AVATAR_SIZES[0]

# Placeholder email minted on SAML/CMD account creation when the IdP did not
# provide an email (or the CMD email is already taken). Mint and detection
# must always use these constants so they can never drift.
SAML_PLACEHOLDER_EMAIL_PREFIX = "saml-"
SAML_PLACEHOLDER_EMAIL_DOMAIN = "autenticacao.gov.pt"

# `extras` key naming which government identity provider an account last
# authenticated through: AUTH_PROVIDER_CMD or AUTH_PROVIDER_EIDAS. Written from
# the ACS route that received the assertion, which is the only place that knows
# -- the two routes converge downstream and the assertion attributes look the
# same afterwards, so nothing below them can infer it.
#
# ABSENT MEANS ABSENT. Accounts that authenticated before this field existed
# carry no value until their owner signs in again, and no code may substitute a
# default for a missing one: guessing "everyone is CMD because eIDAS is rarer"
# stores a supposition that reads as a fact, and the question this field exists
# to answer ("how many people use eIDAS?") would then be answered wrongly with
# nobody able to tell.
#
# It does NOT distinguish a national from a foreign CMD citizen, and must not be
# extended to. Both arrive on the same ACS route, and the attributes that would
# tell them apart (MDC DocType / DocNationality / DocNumber) are not requested
# yet. Inferring "foreign" from a missing NIC would be wrong twice over: it is a
# deduction from the attributes rather than the route, and a CMD assertion with
# no NIC is also what a misconfigured IdP produces. That dimension belongs in
# its own keys, added when those attributes start arriving -- which keeps every
# value written here correct instead of needing a rewrite.
AUTH_PROVIDER = "auth_provider"
AUTH_PROVIDER_CMD = "cmd"
AUTH_PROVIDER_EIDAS = "eidas"
