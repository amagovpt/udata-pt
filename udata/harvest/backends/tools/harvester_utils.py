# -*- coding: utf-8 -*-
import logging
import mimetypes
import random
import re
import time
import unicodedata
from datetime import datetime
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

import requests

from udata.core.contact_point.models import ContactPoint
from udata.core.dataset.constants import UpdateFrequency
from udata.core.spatial.models import SpatialCoverage
from udata.models import License, Organization, Resource

log = logging.getLogger(__name__)


def with_http_retry(backend, func, *args, **kwargs):
    """Call `func` retrying connection-level failures, like `BaseBackend.get`.

    For network calls issued by third-party clients (e.g. owslib's
    `CatalogueServiceWeb` / `getrecords2`, which use `requests` internally
    but bypass the guarded `BaseBackend` session). Retries the same
    exception set as `BaseBackend._request_with_retry` — connection errors,
    timeouts and truncated bodies — with exponential backoff and jitter,
    driven by the same `HARVEST_HTTP_*` settings via the backend properties.
    SSL errors, HTTP status errors and OGC ServiceExceptions are never
    retried. The caller remains responsible for `_guard_url` checks.
    """
    delay = backend.http_retry_initial_delay
    max_delay = backend.http_retry_max_delay
    max_retries = backend.http_max_retries

    for attempt in range(1, max_retries + 1):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.SSLError:
            # Certificate errors are not transient: fail immediately.
            raise
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ChunkedEncodingError,
        ) as e:
            if attempt >= max_retries:
                raise
            log.warning(
                "%s failed (attempt %s/%s), retrying: %s",
                getattr(func, "__name__", repr(func)),
                attempt,
                max_retries,
                e,
            )
            time.sleep(min(delay + random.uniform(0, 0.1 * delay), max_delay))
            delay = min(delay * 2, max_delay) if delay else 1


def normalize_url_slashes(url: str) -> str:
    """
    Replace all backslashes in a URL with forward slashes.
    Remove any accidental multiple slashes after the protocol.
    """
    if not url:
        return url
    # Substitui todos os tipos de backslash por slash
    url = url.replace("\\", "/")
    # Separa protocolo do resto
    parts = url.split("://", 1)
    if len(parts) == 2:
        # Remove múltiplos slashes seguidos no caminho (mas não no protocolo)
        parts[1] = re.sub(r"/+", "/", parts[1])
        return "://".join(parts)
    else:
        return re.sub(r"/+", "/", url)


def _url_key(url: str) -> str:
    """Comparison key for resource URLs: normalized slashes, no outer spaces."""
    return normalize_url_slashes((url or "").strip()).strip()


def sync_resources(dataset, entries: list[dict]) -> None:
    """Reconcile `dataset.resources` with the harvested `entries`, in place.

    Each entry is a dict of `Resource` field values and must carry a `url`. An
    entry matches an existing resource when the two URLs agree once normalized;
    that resource object is then kept — and with it its `id`, hence the
    `/api/1/datasets/r/<id>` permalink users copy and external integrations
    consume — and only its fields are refreshed.

    Harvesters used to do `dataset.resources = []` and rebuild every resource
    from scratch, and since `Resource.id` is an `AutoUUIDField` that mints a new
    UUID on every creation, each nightly run silently broke every permalink of
    the dataset (LEDG-2251). Matching by URL follows the `odspt` backend, which
    already reuses resources through `get_resource()`; dropping the entries that
    vanished upstream follows `ckanpt`.

    Resources absent from `entries` are removed, **except hosted ones**: those
    were uploaded through the portal, never belonged to the harvester, and
    deleting them would both lose the file and orphan it in storage.
    """
    available = list(dataset.resources)
    synced = []
    seen = set()

    for entry in entries:
        fields = dict(entry)
        url = _url_key(fields.pop("url", None))
        # A resource without a URL cannot be stored, and a URL harvested twice
        # describes the same resource: keeping both would leave the duplicate
        # matchless — and therefore with a brand new id — on the next run.
        if not url or url in seen:
            continue
        seen.add(url)
        fields["url"] = url

        resource = next((r for r in available if _url_key(r.url) == url), None)
        if resource is None:
            resource = Resource(**fields)
        else:
            available.remove(resource)
            for name, value in fields.items():
                setattr(resource, name, value)
        synced.append(resource)

    # Files uploaded on the portal are not part of the harvested payload.
    synced.extend(resource for resource in available if resource.filetype == "file")

    # Rebinding the list is not a wipe: these are the very same `Resource`
    # objects, so their ids survive. It also reorders them after the source and
    # drops whatever upstream no longer publishes.
    dataset.resources = synced


def collapse_duplicated_path(url: str) -> str:
    """Drop a path tail that upstream metadata emitted twice in a row.

    Some catalogues publish links whose path was concatenated with itself,
    e.g. `.../geoportaldocs/_Clima/Portal/meta.xlsx_Clima/Portal/meta.xlsx`
    (LEDG-2250). The doubled link 404s while the single one resolves, so the
    repetition is stripped before the URL reaches a resource.

    Only a tail spanning **more than one path segment** is collapsed: a single
    repeated segment (`/reports/reports`) is a plausible real path, whereas a
    multi-segment path repeating itself verbatim at the very end is not. The
    longest such repetition wins. Scheme, host, query and fragment are left
    untouched — the defect only ever affects the path.
    """
    if not url:
        return url
    parts = urlsplit(url)
    path = parts.path
    length = len(path)
    for half in range(length // 2, 0, -1):
        tail = path[length - half :]
        if path[length - 2 * half : length - half] != tail:
            continue
        # Require the repeated tail to cross a segment boundary.
        if "/" not in tail.strip("/"):
            continue
        return urlunsplit(parts._replace(path=path[: length - half]))
    return url


# The licence a harvester backend last wrote. Without it, a licence the
# harvester derived and one a producer corrected by hand are the same value in
# the database, and the fallback below cannot tell them apart.
DERIVED_LICENSE_EXTRA = "harvest:derived_license"


def settle_harvested_license(dataset, resolved):
    """The licence to store, given what the source grants (`resolved`, or `None`).

    Source first, then a correction a producer made by hand, then the portal
    default. It never falls back to `cc-by` -- that constant was the bug, and
    `notspecified` is what the portal says when it does not know.

    The middle step is the delicate one. Keeping whatever the dataset already
    carries is what lets a producer's correction survive a harvest, but applied
    blindly it also makes the licence irrevocable: a source that stops granting
    CC BY would never take it back, because the value we wrote ourselves last
    night is indistinguishable from an editorial decision. So what the harvester
    derived is recorded, and only a licence that differs from it is treated as
    somebody's correction.

    Resolving the source's own text into a licence stays with each backend,
    which is the only part that knows where its source declares one.
    """
    if resolved is not None:
        dataset.extras[DERIVED_LICENSE_EXTRA] = resolved.id
        return resolved

    # The source grants nothing. Anything on the dataset that is not what we
    # last wrote is a correction, and stays.
    current = dataset.license
    if current is not None and current.id != dataset.extras.get(DERIVED_LICENSE_EXTRA):
        dataset.extras.pop(DERIVED_LICENSE_EXTRA, None)
        return current

    # `default` has to be a document: Dataset.license is a ReferenceField and a
    # raw string raises (LEDG-2315).
    default = License.default()
    if default is not None:
        dataset.extras[DERIVED_LICENSE_EXTRA] = default.id
    return default


def resolve_publisher_organization(
    backend, acronym: str, name: str | None = None, description: str | None = None
) -> Organization | None:
    """Return the local organization for a remote publisher `acronym`.

    Existing organizations are matched by acronym. A new one is created only
    outside a dryrun, with `name` and `description` when the source carries
    them and the acronym itself when it does not -- the ODS feed has no
    publisher title or description, only the acronym. `None` means the caller
    must leave `dataset.organization` alone.

    A preview creates nothing, so an organization that does not exist yet cannot
    be shown on the item: `organization` is a `ReferenceField` and mongoengine
    refuses to reference an unsaved document, which would fail the whole item on
    the `validate()` a dryrun runs instead of `save()`. Same reasoning as
    upstream for contact points (`contact_points_from_rdf`).

    The field is left untouched rather than set to `None`, which means it keeps
    whatever `get_dataset` seeded from the source -- so the item shows the
    source's organization while a real run would file the dataset under a new
    one. That is exactly the question a preview is used to answer, so it is said
    out loud: `process_dataset` collects these onto `item.logs`, which the
    preview API returns.

    `warning`, not `info`: `init_logging` puts the app logger at WARNING outside
    debug, and the collector hangs off that logger - an `info` would be dropped
    before it ever became a record. Warning is also the honest level here, and
    this branch only runs on a preview, so it cannot become noise on a scheduled
    harvest.
    """
    organization = Organization.objects(acronym=acronym).first()
    if organization:
        return organization
    if backend.dryrun:
        log.warning(
            "Organization %s does not exist yet; a real harvest would create it, "
            "the preview does not",
            # `repr` and bounded, like the other warnings here: the value is
            # remote and these records are returned in the preview response.
            repr(acronym)[:200],
        )
        return None
    # `is not None`, not `or`: a source that publishes an empty title or
    # description keeps it empty, as it does today. Only a field the source does
    # not carry at all falls back to the acronym.
    organization = Organization(
        acronym=acronym,
        name=name if name is not None else acronym,
        description=description if description is not None else acronym,
    )
    organization.save()
    return organization


def attach_publisher_contact(backend, dataset, name: str | None, email: str | None) -> None:
    """Attach the `publisher` contact point `name`/`email` to `dataset`.

    Extracted from `ogc.py`, where it was written first, so DGT does not carry a
    second copy of the `dryrun` handling. The contact point belongs to the
    dataset's organization, or to its owner; with neither there is nothing to
    attach it to and the call does nothing.

    A preview creates nothing: it only reuses an existing contact point, never
    mints one. Mongoengine cannot reference an unsaved document, so there is
    nothing to put on the item when none matches -- the same guard upstream
    applies in `contact_points_from_rdf` for the DCAT path.

    `get()`, not `first()`: `get_or_create` ends on a `get`, so duplicates
    matching this query fail a real run. Predicting that failure is the
    preview's job -- `first()` would quietly pick one of them and report the
    item as fine.

    Contact points are only ever added: one the source no longer publishes stays
    on the dataset.
    """
    if email:
        email = email.replace("mailto:", "").strip()
    if not (name or email):
        return

    if dataset.organization:
        org_or_owner = {"organization": dataset.organization}
    elif dataset.owner:
        org_or_owner = {"owner": dataset.owner}
    else:
        return

    if backend.dryrun:
        try:
            contact = ContactPoint.objects.get(
                name=name, email=email, role="publisher", **org_or_owner
            )
        except ContactPoint.DoesNotExist:
            contact = None
    else:
        contact, _ = ContactPoint.objects.get_or_create(
            name=name, email=email, role="publisher", **org_or_owner
        )

    if contact:
        if not dataset.contact_points:
            dataset.contact_points = []
        if contact not in dataset.contact_points:
            dataset.contact_points.append(contact)


def build_resource_url(raw_url: str) -> str:
    """Turn a raw `dct:references` link into the URL published on the resource.

    The catalogue hands out Windows-style separators and, on at least one
    record, a path concatenated with itself -- that doubled link 404s while the
    single one downloads (LEDG-2250). Both defects are repaired here so the
    resource URL matches what the origin actually serves.

    Only the path is touched. `normalize_url_slashes` collapses every run of
    slashes in everything after the scheme, which rewrites a URL nested in a
    query string -- `?url=https://other/y` becomes `?url=https:/other/y` -- and
    geoportals nest URLs in query strings all the time, in map proxies and
    `GetMap` requests. That function is left as it is because `_url_key` and
    three other backends rely on its exact output; what it is wrong about is
    repairing a URL, which is this one's job.
    """
    if not raw_url:
        return raw_url
    parts = urlsplit(raw_url.replace("\\", "/"))
    repaired = urlunsplit(parts._replace(path=re.sub(r"/+", "/", parts.path)))
    return collapse_duplicated_path(repaired)


# Query-string service values that identify an OGC endpoint, e.g.
# `...?SERVICE=WMS&REQUEST=GetCapabilities`.
OGC_SERVICE_FORMATS = frozenset({"wms", "wfs", "wcs", "wmts", "csw"})


def guess_url_format(url: str, fallback: str = "remote") -> str:
    """Derive a resource format from `url`, or `fallback` when unknown.

    An OGC `SERVICE=` query parameter wins over the file extension, since
    those endpoints carry no extension at all. Otherwise the extension is read
    from the **last path segment only** — reading it off the whole URL picks up
    dots from the host name and from query strings, which is how `.xlsx`
    documents ended up published as WMS services (LEDG-2250).
    """
    if not url:
        return fallback
    parts = urlsplit(url)
    query = {key.lower(): value for key, value in parse_qs(parts.query).items()}
    service = (query.get("service") or [""])[0].strip().lower()
    if service in OGC_SERVICE_FORMATS:
        return service
    name = unquote(parts.path).rsplit("/", 1)[-1]
    if "." in name:
        extension = name.rsplit(".", 1)[-1].strip().lower()
        # Anything else is upstream noise (`.pdf_Relatorio_2`, truncated paths).
        if extension.isalnum() and len(extension) <= 5:
            return extension
    return fallback


# INE publishes the update frequency of every indicator as free Portuguese text in
# `<periodicity>`. Mapping it onto our controlled vocabulary is shared by the two INE
# backends (`ine`, `inehvd`), which read the same catalogue.
#
# The map is closed over the values actually published: the full catalogue
# (`xml_indic.jsp?opc=2`) was enumerated on 2026-09-18 and carries 15 distinct values over
# 13154 indicators — anual 7158, decenal 1786+1, mensal 1420, não periódica 1025+1,
# trimestral 605, bienal 419, sexenal 414, quinquenal 276, semestral 19, quadrienal 11,
# mensal acumulado 10, trienal 7, semanal 2. Re-run that enumeration before assuming a
# value is absent; anything unmapped degrades to UNKNOWN rather than failing the item.
#
# Two properties of the feed drive the normalisation below, and both are load-bearing:
# 13152 of the 13154 values carry surrounding whitespace (`<![CDATA[ Mensal]]>`), and the
# same value appears in different capitalisations (`Decenal`/`decenal`,
# `Não periódica`/`Não Periódica`).

# The MIME types the harvested sources publish, mapped to the portal's format
# names. Curated on purpose, and consulted before `mimetypes`: the standard
# library answers `application/xml` with `.xsl`, which is an artefact of its
# table rather than the format of the resource, and it knows none of the
# `application/csv|xls|xlsx` spellings the sources use.
MIME_FORMATS = {
    "application/json": "json",
    "application/ld+json": "jsonld",
    "application/xml": "xml",
    "text/xml": "xml",
    "application/csv": "csv",
    "text/csv": "csv",
    "application/xls": "xls",
    "application/xlsx": "xlsx",
    "application/geo+json": "geojson",
    "application/gml+xml": "gml",
}


def guess_format_from_mime(
    mime: str | None, url: str | None = None, fallback: str | None = None
) -> str | None:
    """Derive a resource format from a MIME type, falling back to `url`.

    The single MIME-to-format guess for every harvest backend: the curated
    table first, then `mimetypes`, then the URL through `guess_url_format` -
    the single URL guess - and `fallback` when nothing resolves. The result is
    always lower case; a backend that publishes formats differently maps the
    result itself rather than guessing again.
    """
    if mime:
        # Normalized once, for both lookups: `mimetypes` answers `None` to
        # anything with surrounding whitespace or an upper-cased type.
        normalized = mime.strip().lower()
        mapped = MIME_FORMATS.get(normalized)
        if mapped:
            return mapped
        extension = mimetypes.guess_extension(normalized)
        if extension:
            return extension.lstrip(".").lower()
    if url:
        return guess_url_format(url, fallback=fallback)
    return fallback


INE_PERIODICITY: dict[str, UpdateFrequency] = {
    "anual": UpdateFrequency.ANNUAL,
    "mensal": UpdateFrequency.MONTHLY,
    # Accumulated monthly figures are still published monthly.
    "mensal acumulado": UpdateFrequency.MONTHLY,
    "trimestral": UpdateFrequency.QUARTERLY,
    "semestral": UpdateFrequency.SEMIANNUAL,
    "semanal": UpdateFrequency.WEEKLY,
    "bienal": UpdateFrequency.BIENNIAL,
    "trienal": UpdateFrequency.TRIENNIAL,
    "quadrienal": UpdateFrequency.QUADRENNIAL,
    "quinquenal": UpdateFrequency.QUINQUENNIAL,
    "decenal": UpdateFrequency.DECENNIAL,
    "não periódica": UpdateFrequency.IRREGULAR,
    # `UpdateFrequency` has no six-yearly member (it jumps QUINQUENNIAL -> DECENNIAL), so
    # the 414 indicators published as "Sexenal" land on OTHER. Not UNKNOWN: the source does
    # state a frequency, and `Dataset.has_frequency` counts UNKNOWN as "no frequency given".
    "sexenal": UpdateFrequency.OTHER,
    # Not observed in the catalogue on 2026-09-18, kept so the mapping does not regress:
    # "diário" is the one value the previous `inehvd.map_frequency` recognised.
    "diário": UpdateFrequency.DAILY,
    "diario": UpdateFrequency.DAILY,
    "bimestral": UpdateFrequency.BIMONTHLY,
    "ocasional": UpdateFrequency.IRREGULAR,
}

# Warn once per unseen value: a single INE harvest walks ~13k indicators, and an unmapped
# periodicity would otherwise log once per dataset. Reset per harvest by
# `reset_ine_periodicity_warnings`, so a value that is still unmapped is reported again on
# the next run instead of being silenced for the lifetime of the Celery worker.
_warned_periodicities: set[str] = set()


def reset_ine_periodicity_warnings() -> None:
    """Let the next harvest report unmapped periodicities again."""
    _warned_periodicities.clear()


def map_ine_periodicity(text: str | None) -> UpdateFrequency:
    """Map INE's `<periodicity>` text onto `UpdateFrequency`.

    Returns `UpdateFrequency.UNKNOWN` for empty, missing or unrecognised values and never
    raises: a periodicity we cannot name must not fail the item being harvested.

    Matching is exact on the stripped, case-folded text rather than a substring test. The
    previous per-backend implementation used `"mensal" in text`, which silently swallowed
    "Mensal acumulado" and would misread any future compound value the same way.
    """
    if not text:
        return UpdateFrequency.UNKNOWN

    # NFC first: the map's keys are composed, and the feed's encoding is not something to
    # trust — `INEBackend._normalize_tag` decomposes for the same reason. Without this, a
    # decomposed "Não periódica" would miss the lookup and send 1026 indicators to UNKNOWN.
    key = unicodedata.normalize("NFC", text).strip().casefold()
    if not key:
        return UpdateFrequency.UNKNOWN

    frequency = INE_PERIODICITY.get(key)
    if frequency is None:
        if key not in _warned_periodicities:
            _warned_periodicities.add(key)
            log.warning("Unmapped INE <periodicity> value: %r", text.strip())
        return UpdateFrequency.UNKNOWN

    return frequency


# A degenerate bounding box -- a single point -- still has to be stored as a
# polygon, because `SpatialCoverage.geom` is a MultiPolygonField. Roughly 11
# metres at the equator, the same value `cswudata` uses.
POINT_EPSILON = 0.0001


def bbox_to_multipolygon(boxes: list[tuple[float, float, float, float]]) -> dict:
    """Build a GeoJSON MultiPolygon from one or more `(minx, miny, maxx, maxy)`.

    Each box becomes one ring, wound counter-clockwise and closed, in `[lon,
    lat]` order. A box whose corners coincide is widened by `POINT_EPSILON`
    first, since a zero-area ring is not a polygon.

    Extracted from `cswudata._process_spatial`, which builds the same geometry
    inline from an owslib bbox object; sources that publish the corners as
    plain numbers -- DGT's `geoBox` -- have nothing to call otherwise.
    """
    polygons = []
    for minx, miny, maxx, maxy in boxes:
        minx, miny, maxx, maxy = float(minx), float(miny), float(maxx), float(maxy)
        if minx > maxx:
            minx, maxx = maxx, minx
        if miny > maxy:
            miny, maxy = maxy, miny
        if minx == maxx and miny == maxy:
            minx -= POINT_EPSILON
            miny -= POINT_EPSILON
            maxx += POINT_EPSILON
            maxy += POINT_EPSILON
        polygons.append(
            [
                [
                    [minx, miny],
                    [maxx, miny],
                    [maxx, maxy],
                    [minx, maxy],
                    [minx, miny],
                ]
            ]
        )
    return {"type": "MultiPolygon", "coordinates": polygons}


def _is_geographic_box(box) -> bool:
    """Whether `box` is four coordinates on Earth, in degrees.

    Also what rejects `nan` and `inf`, which `float` parses happily: every
    comparison against NaN is false, and the infinities fall outside the bounds.
    A non-finite or projected corner would otherwise reach `SpatialCoverage.geom`
    intact and fail the item at save time, or put the dataset several thousand
    degrees off the map -- `spatial.geom` carries no 2dsphere index to refuse it.
    """
    try:
        minx, miny, maxx, maxy = (float(value) for value in box)
    except (TypeError, ValueError):
        return False
    return -180 <= minx <= 180 and -180 <= maxx <= 180 and -90 <= miny <= 90 and -90 <= maxy <= 90


def bbox_to_spatial_coverage(
    boxes: list[tuple[float, float, float, float]],
) -> SpatialCoverage | None:
    """The `SpatialCoverage` for one or more `(minx, miny, maxx, maxy)` boxes.

    The one step every backend reading a bounding box ends with -- DGT's
    `geoBox`, the OGC `GeoShape.box`, the ODS `metas.bbox` -- so each of them
    only has to parse its own source's shape. Boxes that are not geographic are
    dropped, and `None` is returned when none is left: the caller then keeps
    whatever coverage the dataset already had rather than replacing it with
    nothing.
    """
    valid = [box for box in boxes if _is_geographic_box(box)]
    if not valid:
        return None
    return SpatialCoverage(geom=bbox_to_multipolygon(valid))


# ISO 19115 publishes the update frequency as the `MD_MaintenanceFrequencyCode`
# codelist, which the SNIG index copies verbatim into `updateFrequency`. The
# codelist is closed, so the map below is the whole of it rather than only the
# values seen in one sample -- unlike `INE_PERIODICITY` above, which maps free
# Portuguese text and can only ever be closed over what was observed.
#
# Filled on 42.4% of the DGT index (509 of 1200 records enumerated for
# LEDG-2530): asNeeded 317, notPlanned 135, unknown 18, daily 14, continual 13,
# annually 9, biannually 4, irregular 1.
#
# Four of the codelist terms have no same-named member in `UpdateFrequency` and
# are mapped explicitly:
#   `asNeeded`   -> PUNCTUAL, which the enum itself annotates `# EU:AS_NEEDED`
#   `continual`  -> CONTINUOUS, annotated `# EU:UPDATE_CONT`
#   `annually`   -> ANNUAL
#   `biannually` -> SEMIANNUAL. ISO 19115 defines it as "data is updated twice
#                   each year", and udata already reads the legacy id
#                   `biannual` as SEMIANNUAL. The English word is also used for
#                   "every two years", so this is the one entry worth checking
#                   against the source if a record looks wrong.
ISO_MAINTENANCE_FREQUENCY: dict[str, UpdateFrequency] = {
    "continual": UpdateFrequency.CONTINUOUS,
    "daily": UpdateFrequency.DAILY,
    "weekly": UpdateFrequency.WEEKLY,
    "fortnightly": UpdateFrequency.BIWEEKLY,
    "monthly": UpdateFrequency.MONTHLY,
    "quarterly": UpdateFrequency.QUARTERLY,
    "biannually": UpdateFrequency.SEMIANNUAL,
    "annually": UpdateFrequency.ANNUAL,
    "asneeded": UpdateFrequency.PUNCTUAL,
    "irregular": UpdateFrequency.IRREGULAR,
    "notplanned": UpdateFrequency.NOT_PLANNED,
    "unknown": UpdateFrequency.UNKNOWN,
    # Later additions to the codelist (ISO 19115-1), published by some
    # GeoNetwork catalogues.
    "semimonthly": UpdateFrequency.SEMIMONTHLY,
    "biennially": UpdateFrequency.BIENNIAL,
    # "periodically at some interval", with no interval given: the source does
    # state a frequency, so OTHER rather than UNKNOWN -- `Dataset.has_frequency`
    # counts UNKNOWN as no frequency at all.
    "periodic": UpdateFrequency.OTHER,
}

# Warn once per unseen value, reset per harvest, for the same reason as
# `_warned_periodicities` above.
_warned_maintenance_frequencies: set[str] = set()


def reset_maintenance_frequency_warnings() -> None:
    """Let the next harvest report unmapped maintenance frequencies again."""
    _warned_maintenance_frequencies.clear()


def map_iso_maintenance_frequency(text: str | None) -> UpdateFrequency:
    """Map an ISO 19115 `MD_MaintenanceFrequencyCode` onto `UpdateFrequency`.

    Returns `UpdateFrequency.UNKNOWN` for empty, missing or unrecognised values
    and never raises: a frequency we cannot name must not fail the item.

    The codelist terms are camelCase (`asNeeded`, `notPlanned`), and catalogues
    differ on the casing, so the lookup is on the case-folded text with any
    separator removed -- `asNeeded`, `as needed` and `AS_NEEDED` are one value.
    """
    if not text:
        return UpdateFrequency.UNKNOWN

    key = re.sub(r"[\s_-]+", "", unicodedata.normalize("NFC", text).strip().casefold())
    if not key:
        return UpdateFrequency.UNKNOWN

    frequency = ISO_MAINTENANCE_FREQUENCY.get(key)
    if frequency is None:
        if key not in _warned_maintenance_frequencies:
            _warned_maintenance_frequencies.add(key)
            log.warning("Unmapped ISO maintenance frequency: %r", text.strip())
        return UpdateFrequency.UNKNOWN

    return frequency


# INE publishes `<dates><last_update>` as dd-mm-yyyy.
INE_DATE_FORMAT = "%d-%m-%Y"


def parse_ine_date(text: str | None) -> datetime | None:
    """Parse an INE `dd-mm-yyyy` date, day first. Returns `None` if it cannot be read.

    Deliberately not left to `safe_harvest_datetime`: that helper goes through
    `dateutil.parser.parse` without `dayfirst`, which reads "04-02-2026" as 2 April rather
    than 4 February. Measured against the full catalogue on 2026-09-18, 4930 of the 13154
    published dates are ambiguous under that reading and 4615 of them would be stored as a
    silently different day. `dkan.py` already passes `dayfirst=True` for the same reason;
    here the format is fixed, so an exact parse is both stricter and cheaper.

    Callers pass the result through `safe_harvest_datetime` to pick up the naive-UTC
    normalisation and the future-date guard.
    """
    if not text:
        return None

    try:
        return datetime.strptime(text.strip(), INE_DATE_FORMAT)
    except ValueError:
        log.warning("Unparseable INE <last_update> value: %r", text.strip())
        return None
