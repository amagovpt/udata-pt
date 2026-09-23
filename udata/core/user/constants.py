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
# extended to. Both arrive on the same ACS route. Inferring "foreign" from a
# missing NIC would be wrong twice over: it is a deduction from the attributes
# rather than the route, and a CMD assertion with no NIC is also what a
# misconfigured IdP produces. That dimension lives in its own keys, below --
# which keeps every value written here correct instead of needing a rewrite.
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


# `extras` keys describing the document a FOREIGN citizen's CMD identity is
# built from. They arrive together with AUTH_PROVIDER_CMD and are written only
# when the document -- not a NIC -- was what identified the person.
#
# ABSENT MEANS ABSENT, and here the trap is sharper than for AUTH_PROVIDER: a
# missing value does NOT mean "national". It also covers every account that
# signed in before these attributes were requested, and every assertion that
# arrived without them. Counting absences as nationals would turn a gap in the
# data into a population figure.
#
# The document NUMBER is deliberately not among them. It is the personal part
# of the identity and it lives only inside the HMAC digest in `auth_nic`;
# storing it in the clear next to the type and the nationality would undo the
# reason the identifier is hashed at all. (It does travel in the signed -- not
# encrypted -- session cookie during the migration wizard, exactly as a NIC
# already does today; that is the same exposure, not a new one.)
#
# These are the VERIFIED counterpart of AUTH_CITIZEN_DECLARED: where the two
# disagree, these win, and the disagreement is itself the signal that an IdP is
# misconfigured.
AUTH_DOC_TYPE = "auth_doc_type"
AUTH_DOC_NATIONALITY = "auth_doc_nationality"

# The member state whose eIDAS node asserted the identity: the first segment of
# the PersonIdentifier, which the eIDAS profile RECOMMENDS be shaped
# "<origin>/<destination>/<id>" -- a Czech citizen signing in here arrives as
# "CZ/PT/<uuid>".
#
# 🚩 A SEPARATE KEY FROM AUTH_DOC_NATIONALITY ON PURPOSE, and the reason is
# stronger than "they are similar things". That one is not a nationality at
# all: DocNationality is FORCED to "PT" on residence permits and residence
# cards (see _compose_foreign_identifier), so a Brazilian holding a Portuguese
# residence permit is stored as "PT". Folding the two together would make a
# count of "PT" sum three different populations -- a real nationality, a forced
# value, and an issuing member state -- and answer no question at all.
#
# And the asymmetry settles it: merging two keys later is trivial, separating
# them later is impossible, because nothing would say which rows came from
# which source.
#
# ABSENT MEANS ABSENT, with three distinct causes and no way to tell them
# apart: an account that signed in before this key existed; an identifier that
# did not match the recommended shape (the shape is a recommendation, not a
# guarantee); and a NIC arriving through the eIDAS route, which is accepted
# there and carries no country.
#
# 🚨 AND THERE IS NO BACKFILL. The identifier survives only as the one-way
# digest in auth_nic, so the country cannot be recovered from what is stored.
# Accounts that predate this gain the key only when their own owner signs in
# again -- the same semantics as AUTH_PROVIDER above -- and never otherwise.
AUTH_EIDAS_ORIGIN_COUNTRY = "auth_eidas_origin_country"

# `extras` key holding WHEN the account last dismissed the optional CMD/eIDAS
# linking invite, as an ISO-8601 UTC string.
#
# A DATE AND NOT A BOOLEAN, and that is the whole design. "Dismissed: yes" can
# only express two frequencies, and both are wrong: show it again on the next
# sign-in, which teaches people to click it away without reading, or never
# show it again, which loses them silently before the portal requires a single
# account per person. A date lets the rule be stated -- and the rule is written
# next to it, in MIGRATION_INVITE_REMIND_AFTER, rather than left implicit
# in a comparison somewhere.
#
# Dismissing is NOT the same as declining. The invite is optional and the
# account keeps working either way; what this records is "not now", and the
# portal keeps a permanent way back for the person who changes their mind.
#
# ABSENT MEANS NEVER DISMISSED, which is why it is only ever written and never
# defaulted: an account that has not seen the invite and an account that
# dismissed it long ago are different states, and the second one comes back.
MIGRATION_INVITE_DISMISSED_AT = "migration_invite_dismissed_at"
