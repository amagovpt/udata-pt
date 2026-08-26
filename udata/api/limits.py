"""Rate-limit helpers for content-creation API endpoints.

Centralizes the `key_func` and the per-endpoint limit constants so all
content-creation endpoints share a consistent abuse-prevention strategy.

See TICKET-59 / VULN-2078 (community resources) and TICKET-1728 / VULN-2083
(discussions) for context.
"""

from flask_limiter.util import get_remote_address
from flask_security import current_user

# Per-endpoint limit profiles.
# Format: "<count> per <window>; ..." understood by flask-limiter.
#
# These are conservative defaults sized for human use. Calibrate against
# legitimate traffic before tightening further.
# Identity poll (`GET /api/1/me/`). The frontend calls this on every page load
# through a server-side proxy (`frontend/src/app/me/route.ts`), so without an
# explicit per-endpoint limit it falls under the IP-keyed global default
# (`RATELIMIT_DEFAULT`). Behind that proxy every user collapses into a single
# IP bucket, exhausting the shared ceiling and returning 429 — which the
# frontend reads as "logged out". Keyed by `user_or_ip` each authenticated user
# gets their own generous bucket sized for legitimate navigation.
IDENTITY_READ_LIMIT = "60 per minute; 1200 per hour"
# Public, anonymous, idempotent search/list reads that populate the listing
# pages (`GET /api/1/datasets|organizations|reuses/?q=...`). Without an explicit
# per-endpoint limit these fall under the IP-keyed `RATELIMIT_DEFAULT`
# ("200 per hour"). Behind the F5/WAF every visitor collapses into one origin IP
# (docs/infra-adc-waf-impact-ppr-prd.md, incident 4.2), so that 200/hour becomes
# a SHARED ceiling across all anonymous visitors per endpoint: the 200th search
# of the hour returns 429 and the page stops populating for everyone. Anonymous
# traffic cannot be keyed per user, so the only lever is a much higher ceiling
# sized for aggregate public browsing; `user_or_ip` still gives logged-in users
# their own bucket. NOTE: this is an aggregate cap under IP-collapse — calibrate
# against real traffic and pair with response caching (ISR + Flask-Caching) so
# repeated queries never reach the limiter. The per-minute ceiling is kept well
# above the old 200/hour burst capacity (so a legitimate spike never regresses
# vs the default) and there is deliberately NO per-day cap: under IP-collapse a
# daily cap would become a site-wide ceiling that blocks every anonymous
# visitor late in the day — exactly the failure mode this fix removes.
PUBLIC_SEARCH_LIMIT = "300 per minute; 6000 per hour"
# Public, anonymous file downloads: the resource "latest" redirect
# (`GET /api/1/datasets/r/<id>`) and the SSRF-guarded external download proxy
# (`GET /api/1/datasets/proxy/download/`). These are the single most frequent
# legitimate public action (every "download" button + harvesters/integrations
# pulling the permanent `latest` link) and, unlike the listing pages, they are
# NOT cacheable (each request is a distinct file/stream), so the limiter is the
# only structural defense. Without an explicit limit they fall under the
# IP-keyed `RATELIMIT_DEFAULT` ("200 per hour"), which collapses to a shared
# site-wide ceiling behind the F5/WAF (docs/infra-adc-waf-impact-ppr-prd.md,
# incident 4.2) and returns 429 to everyone after 200 aggregated downloads/hour.
# Sized generously and keyed by `user_or_ip` (authenticated harvesters get their
# own bucket); deliberately NO per-day cap — under IP-collapse a daily cap would
# become a site-wide daily block, the exact failure mode this fix removes.
RESOURCE_DOWNLOAD_LIMIT = "300 per minute; 6000 per hour"
# Public, anonymous catalog EXPORTS: CSV dumps (`/site/*.csv`,
# `/organizations/<org>/*.csv`) and RDF catalogs (`/site/catalog[.fmt]`,
# `/datasets/<d>/rdf`, `/organizations/<o>/catalog`, `/dataservices/<d>/rdf`).
# These are expensive to generate (full-collection serialization) and rarely
# need to be fetched frequently by a single client, so they get a tighter
# per-minute ceiling than the interactive search/download limits — while still
# sitting far above the old IP-keyed 200/hour default that collapses site-wide
# behind the F5/WAF. Pair with response caching where possible. Keyed by
# `user_or_ip`; no per-day cap (see RESOURCE_DOWNLOAD_LIMIT for the rationale).
EXPORT_LIMIT = "60 per minute; 1200 per hour"
# Public, anonymous syndication FEEDS (`*/recent.atom` for datasets, reuses,
# dataservices and posts). Polled by aggregators/readers, cacheable, and lighter
# than a full export. A moderate ceiling well above the IP-keyed 200/hour default
# so feed polling never collapses site-wide behind the F5/WAF. Keyed by
# `user_or_ip`; no per-day cap (see RESOURCE_DOWNLOAD_LIMIT for the rationale).
FEED_LIMIT = "120 per minute; 2400 per hour"
# Public, anonymous READ endpoints that the SSR/public pages hit live (not ISR
# cached): typeahead `*/suggest/` (fired per keystroke), entity detail reads
# (`/datasets/<id>/`, `/organizations/<org>/`, `/reuses/<reuse>/`,
# `/dataservices/<id>/` and their sub-resources) and the small reference-data
# lists used to build filters (`/datasets/licenses|frequencies|schemas|...`).
# Without an explicit limit these fall under the IP-keyed `RATELIMIT_DEFAULT`
# ("200 per hour"), which behind the F5/WAF collapses to a single site-wide
# bucket (docs/infra-adc-waf-impact-ppr-prd.md §4.2): once aggregate read volume
# crosses it, every anonymous visitor gets 429 and the public pages stop
# rendering. Same generous shape as PUBLIC_SEARCH_LIMIT (these are the same
# class of cheap, high-frequency public reads); keyed by `user_or_ip` so
# logged-in users get their own bucket, and deliberately NO per-day cap (under
# IP-collapse a daily cap becomes a site-wide daily block). Suggest/typeahead
# reuses PUBLIC_SEARCH_LIMIT (it is search-backed); this covers the rest.
PUBLIC_READ_LIMIT = "300 per minute; 6000 per hour"
CONTENT_CREATE_LIMIT = "5 per minute; 30 per hour; 100 per day"
HEAVY_CREATE_LIMIT = "2 per minute; 5 per hour; 10 per day"
# Harvest preview, both routes (`POST /harvest/source/preview/` for a config that
# is not stored yet, `GET /harvest/source/<id>/preview/` for a saved source).
# Unlike the limits above, what this one rations is not writes: these are the
# routes that make the server run a whole harvest backend against a remote
# catalogue, so each request means outbound traffic in the portal's name. That is
# expensive regardless of who asks, which is why they carry a limit even though
# both also require authorization. The two share the constant deliberately —
# they cost the same and the backoffice picks between them by who is asking, so
# a tighter ceiling on one would just be a ceiling on some users.
#
# A separate constant from CONTENT_CREATE_LIMIT even where the numbers coincide
# (COMMENT_CREATE_LIMIT is the same shape for the same reason): the two ceilings
# answer to different things — content creation to abuse of public content, this
# one to outbound cost — and would have to move apart the first time either is
# calibrated. Which happened immediately: 5/min was the first choice and it
# 429'd a test that walks the seven canary URLs of the VULN-2084 replay, so it
# would equally 429 a sysadmin tuning filters and re-previewing after each
# change, which is the actual workflow. 20/min is out of reach for someone
# clicking a button and still an order of magnitude under the 200/h IP-keyed
# default these routes would otherwise fall under. Note the limiter is live in
# the test suite: `RATELIMIT_ENABLED = False` sits in `settings.Debug`, not in
# `settings.Testing`.
#
# Keyed by `user_or_ip`, and since both routes are `@api.secure` the key is
# always `user:{id}` — a per-publisher bucket, so the daily cap never becomes the
# site-wide daily block that the anonymous endpoints above have to avoid.
HARVEST_PREVIEW_LIMIT = "20 per minute; 120 per hour; 400 per day"
COMMENT_CREATE_LIMIT = "5 per minute; 30 per hour; 100 per day"
# File upload on existing/new dataset resources. Keyed by `user_or_ip` and the
# endpoint is authenticated (`@api.secure`), so the key is always `user:{id}` —
# each publisher gets their own bucket (no IP-collapse sharing behind the F5/WAF,
# unlike anonymous read endpoints). Sized for bulk publication: data providers
# routinely upload dozens of files in one session (e.g. 46 xlsx + 46 json), so
# the previous 10/min ceiling 429'd legitimate batch uploads after the 10th file.
# Chunk parts are exempt (see is_chunk_part) so a chunked upload counts once.
UPLOAD_LIMIT = "120 per minute; 600 per hour; 2000 per day"
# Opening a brand-new discussion thread is a much rarer human action than
# adding a comment to an existing one, so it gets a tighter ceiling than
# COMMENT_CREATE_LIMIT. Sized for VULN-2083 audit pattern (100+ Burp
# Intruder POSTs on a single dataset): only the first few succeed inside
# the per-minute window, hourly/daily caps absorb burst-then-pause attacks.
DISCUSSION_CREATE_LIMIT = "3 per minute; 10 per hour; 30 per day"
# Machine-driven metadata writeback from the Hydra crawler (`hydra-pt`): the
# authenticated `PUT/DELETE /api/2/datasets/<d>/resources/<rid>/extras/` (and
# the dataset-level `.../extras/`) callbacks it fires after every check/analysis
# (udata_hydra/utils/http.py `send()`, authenticated via `X-API-KEY`). Unlike a
# human publisher this is one bot re-checking the ENTIRE catalog: a full crawl
# emits a writeback per changed resource, so with many workers it bursts into
# the thousands per minute. Without an explicit limit these writes fall under
# the IP-keyed `RATELIMIT_DEFAULT` ("200 per hour"): the crawler runs from a
# single origin IP, so it exhausts that shared hourly ceiling almost immediately
# and every subsequent callback returns 429 (the bot then drops analysis results
# on the floor). Keyed by `user_or_ip`; because the endpoint is `@apiv2.secure`
# the key is always `user:{id}` (the Hydra bot's API-token identity), so this is
# a per-bot bucket that never collapses with — or starves — other traffic behind
# the F5/WAF. Sized for absurd resource volume; deliberately NO per-day cap (a
# daily cap would become a bot-wide daily block mid-crawl, the exact failure mode
# this fixes). Calibrate against real crawl throughput.
CRAWLER_WRITE_LIMIT = "1200 per minute; 60000 per hour"
# Public, anonymous support-contact form (`POST /site/contact/`). The primary
# anti-automation control is the reCAPTCHA v3 check on the form; this limit is a
# structural backstop that keeps working even when reCAPTCHA is not configured
# (VULN-2089). Sized to stop a submission flood (the pentest PoC sent bursts of
# requests) while staying well above legitimate human use — a person submits the
# contact form a handful of times at most. Keyed by `user_or_ip`; behind the
# F5/WAF anonymous traffic collapses to one origin IP
# (docs/infra-adc-waf-impact-ppr-prd.md), so this is an aggregate ceiling —
# deliberately NO per-day cap (a daily cap would become a site-wide daily block,
# the exact failure mode to avoid on an anonymous endpoint).
CONTACT_SUBMIT_LIMIT = "20 per minute; 200 per hour"


def user_or_ip() -> str:
    """Return a rate-limit key keyed on the authenticated user when present,
    falling back to the remote IP address otherwise.

    Using the user id (instead of the IP alone) prevents bypass by rotating
    proxies/VPNs once the attacker is logged in. API token authentication
    resolves through `current_user` like any other login, so it is covered
    by the same key.
    """
    if current_user.is_authenticated:
        return f"user:{current_user.id}"
    return f"ip:{get_remote_address()}"
