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

# `extras` key holding whether the citizen said they were national or foreign
# when starting a CMD sign-in: AUTH_CITIZEN_NATIONAL or AUTH_CITIZEN_FOREIGN.
#
# SELF-DECLARED. NOT PROOF. It comes from a radio button, travels in a query
# parameter the caller controls, and anyone can open /saml/login?citizen=foreign
# and claim whatever they like. Nothing may decide anything from it: it gates no
# access, selects no authentication path, and never substitutes for verifying an
# identity. It exists to be counted and to be contrasted with a verified value
# later -- the name says `declared` so no reader can mistake it for a fact.
#
# When the MDC document attributes start arriving, the verified value wins on
# disagreement, and a mismatch becomes the signal for a misconfigured IdP: a
# citizen who declares "national" and brings no NIC is far more likely to be a
# broken assertion than a foreign national, which is the ambiguity that
# currently has no way of being resolved.
#
# THE VALUE IS THE LAST ONE DECLARED, not the one declared at this sign-in.
# The write is conditional, so a sign-in that carries no parameter -- someone
# opening /saml/login directly, without the screen -- keeps whatever was there.
# That is deliberate: a direct link must not destroy a good value, and no guess
# is written in its place. Anyone counting these needs to read it as "what this
# person last told us", not "what they told us on their most recent login".
#
# Only the CMD route collects this. The eIDAS sign-in does not ask, and the
# question would not make sense there.
AUTH_CITIZEN_DECLARED = "auth_citizen_declared"
AUTH_CITIZEN_NATIONAL = "national"
AUTH_CITIZEN_FOREIGN = "foreign"

#: The only values accepted from the query parameter. An unrecognised one is
#: dropped -- never stored raw, never replaced by a default -- because a guess
#: written here reads exactly like something the citizen said.
AUTH_CITIZEN_DECLARED_VALUES = frozenset({AUTH_CITIZEN_NATIONAL, AUTH_CITIZEN_FOREIGN})
