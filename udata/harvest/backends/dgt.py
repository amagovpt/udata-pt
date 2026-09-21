import re

from udata.core.utils.sanitization import sanitize_strict
from udata.harvest.backends.base import BaseBackend
from udata.harvest.models import HarvestItem
from udata.models import License

from .tools.harvester_utils import OGC_SERVICE_FORMATS, guess_url_format, sync_resources

# The SNIG index publishes the licence as free text inside `legalConstraints`.
# It is never fed to `License.guess`: that falls back to a Damerau-Levenshtein
# match over every licence slug and title, and free text of a thousand
# characters would resolve to whatever happens to be closest. Instead a
# canonical Creative Commons code is extracted first -- from a licence URL, or
# from the code spelled out in the text -- and only that is looked up.

# Tolerates the two defects the source really carries: the domain misspelled
# `creativecoomons` (two o's, one m), and a version path written `by4.0`
# without the separating slash.
CC_LICENSE_URL_RE = re.compile(
    r"creativec(?:o|oo)m{1,2}ons\.org/licenses/(by(?:-nc)?(?:-sa|-nd)?)/?\d", re.IGNORECASE
)

# `CC-BY-4.0`, `CC BY 4.0`, `CC BY-NC-ND 4.0`, `CC-BY-SA-4.0`, `(CC-BY)`.
CC_LICENSE_CODE_RE = re.compile(r"CC[\s-]?BY(?:[\s-]?NC)?(?:[\s-]?ND|[\s-]?SA)?", re.IGNORECASE)


# A restriction on commercial use that is part of the grant itself, as the
# Azores (SRAAC/DRPM) records word it. Deliberately narrow around the WORD
# "comercial": the SNIT records say "interdita a sua comercializacao" about
# what the portal shows, and matching that would turn the largest slice of the
# source on a restriction that is not aimed at the data.
NON_COMMERCIAL_GRANT_RE = re.compile(
    r"(?:usos?|fins|utiliza[\u00e7c][\u00e3a]o)\s+n[\u00e3a]o[\s-]*comercia"
    r"|proibid[ao]s?\b[^.]{0,200}\b(?:uso|utiliza[\u00e7c][\u00e3a]o)\s+comercial"
    r"|(?:uso|utiliza[\u00e7c][\u00e3a]o)\s+comercial\b[^.]{0,200}\bproibid"
    r"|n[\u00e3a]o\s+(?:\u00e9\s+)?(?:permitid|autorizad)[ao]\b[^.]{0,200}\b(?:uso|utiliza[\u00e7c][\u00e3a]o)\s+comercial"
    r"|non[\s-]?commercial\s+use\s+only",
    re.IGNORECASE,
)

# The source decides how long its own prose is, so the bounds are ours to set.
# Three of the patterns above are of the form `<word>[^.]{0,200}<word>`: the
# gap is bounded because an unbounded `[^.]*` is quadratic in the length of a
# run without a full stop, and legal prose with the stops removed turned into
# 7.9s of CPU per 128 KiB record -- reachable through the harvest preview
# endpoint, which runs synchronously on an HTTP worker.
MAX_CONSTRAINT_ENTRIES = 20
MAX_CONSTRAINT_LENGTH = 5000
# Past this the record is not decided at all rather than decided on a prefix:
# truncating could cut off the very restriction that withholds the licence.
MAX_DECIDABLE_LENGTH = 20000

# Each `link` the SNIG index publishes carries a protocol in field 3 and a MIME
# type in field 4, both free text. Enumerated over the 733 links of a 400-record
# sample on 2026-09-21, field 4 alone spells the same handful of services in
# nine different ways -- `application/vnd.ogc.wms_xml` (327), `text/plain` (243),
# `text/html` (39), `OGC API - Features` (27), `WMS` (20), `wms` (12), `wfs` (12),
# `WFS` (11), `OGC API Maps` (9), `OCG API - Maps` (9, the source's own
# transposition), `WMTS` (8), `OGC:WFS-2.0.0-http-get-capabilities` (5),
# `OGC:WFS` (4) and `n.a` (1). The map is closed over what is actually
# published; re-run that enumeration before assuming a value is absent.
LINK_FORMATS: dict[str, str] = {
    "application/vnd.ogc.wms_xml": "wms",
    "application/vnd.ogc.wfs_xml": "wfs",
    "application/vnd.google-earth.kml+xml": "kml",
    "application/vnd.google-earth.kmz": "kmz",
    "application/geo+json": "geojson",
    "application/json": "json",
    "application/pdf": "pdf",
    "application/xml": "xml",
    "application/zip": "zip",
    "text/csv": "csv",
    "text/html": "html",
    "text/xml": "xml",
    "image/tiff": "tiff",
    # Bare service names, in the casings the source uses.
    "wms": "wms",
    "wfs": "wfs",
    "wcs": "wcs",
    "wmts": "wmts",
    "csw": "csw",
    # OGC API endpoints carry no extension and no `SERVICE=` parameter, so the
    # label is the only thing that names them.
    "ogc api - features": "ogcapi-features",
    "ogc api features": "ogcapi-features",
    "ogc api - maps": "ogcapi-maps",
    "ogc api maps": "ogcapi-maps",
    # `OCG` for `OGC` on 9 of the 733 links sampled. Tolerated for the same
    # reason `CC_LICENSE_URL_RE` tolerates `creativecoomons`: the defect is in
    # the source and is not ours to wait on.
    "ocg api - maps": "ogcapi-maps",
    "ocg api maps": "ogcapi-maps",
}

# Values that name no format at all, and must fall through to the URL rather
# than be believed. `text/plain` is the second most common MIME in the index
# and sits in front of WFS endpoints (161 of 243 sampled), zip archives (48),
# PDFs, HTML pages and XML feeds alike -- reading it as `txt` would replace a
# wrong answer with a confidently wrong one.
UNINFORMATIVE_LINK_FORMATS = frozenset(
    {"text/plain", "application/octet-stream", "n.a", "n/a", "na", "unknown", "-"}
)

# What a format may look like once resolved: a short token, never a fragment of
# a URL. `guess_url_format` already guarantees this for its own return values;
# the check is applied to every branch so that criterion -- no harvested format
# containing `/` or `?` -- holds even if one of the maps above grows a bad entry.
FORMAT_RE = re.compile(r"^[a-z0-9][a-z0-9.+:-]{0,19}$")

# The value `guess_url_format` falls back to, so a resource nothing is known
# about reads the same here as it does in the other backends.
DEFAULT_FORMAT = "remote"


def _named_format(value: str | None) -> str | None:
    """Resolve one of the source's own labels, or `None` if it names nothing."""
    if not value:
        return None

    key = value.strip().casefold()
    if not key or key in UNINFORMATIVE_LINK_FORMATS:
        return None

    named = LINK_FORMATS.get(key)
    if named:
        return named

    # `OGC:WMS`, but also `OGC:WMS-1.3.0-http-get-capabilities` and
    # `OGC:WFS-2.0.0-http-get-capabilities`: the service is the segment between
    # the prefix and the version.
    if key.startswith("ogc:"):
        service = key[len("ogc:") :].split("-", 1)[0]
        if service in OGC_SERVICE_FORMATS:
            return service

    return None


def format_from_link(protocol: str | None, mimetype: str | None, url: str) -> str:
    """Derive a resource format from what the source says about the link.

    The MIME type is tried first, then the protocol, and the URL only last.
    Reading the URL first is what filled the catalogue with formats like
    `pt/idea-api/collections/Ortofoto_2024_SMG`: the previous implementation ran
    `split(".")[-1]` over the *whole* URL, so any endpoint without a file
    extension returned the tail of the host name and the query string. 98 of the
    733 links sampled on 2026-09-21 (13.4%) resolved that way. `guess_url_format`
    reads the extension off the last path segment only, which is the same bug
    LEDG-2250 fixed for `apambiente`.
    """
    for value in (mimetype, protocol):
        named = _named_format(value)
        if named:
            return named if FORMAT_RE.match(named) else DEFAULT_FORMAT

    guessed = guess_url_format(url, fallback=DEFAULT_FORMAT)
    return guessed if FORMAT_RE.match(guessed) else DEFAULT_FORMAT


# The licence THIS backend last wrote. Without it, a licence the harvester
# derived and one a producer corrected by hand are the same value in the
# database, and the fallback below cannot tell them apart.
DERIVED_LICENSE_EXTRA = "harvest:derived_license"

CC_CODE_TO_LICENSE_ID = {
    "by": "cc-by",
    "by-sa": "cc-by-sa",
    "by-nc": "cc-by-nc",
    "by-nc-nd": "cc-by-nc-nd",
    # Neither of these exists in the portal's licence list, deliberately: a
    # record carrying one resolves to an id that is looked up, not found, and
    # logged -- which is visible, unlike silently landing on a near neighbour.
    "by-nd": "cc-by-nd",
    "by-nc-sa": "cc-by-nc-sa",
}

# Codes that already say "no commercial use" or "no derivatives" on their own.
RESTRICTIVE_CC_CODES = frozenset({"by-nc", "by-nc-nd", "by-nd", "by-nc-sa"})


def _cc_codes(entry: str) -> set[str]:
    """Every Creative Commons code this entry declares.

    Both branches are read rather than the first that answers: a text granting
    CC BY-NC while linking creativecommons.org/licenses/by/4.0 as boilerplate
    would otherwise be read as the more permissive of the two, purely because
    the URL happens to be looked at first.
    """
    codes = {match.group(1).lower() for match in CC_LICENSE_URL_RE.finditer(entry)}
    for match in CC_LICENSE_CODE_RE.finditer(entry):
        # `CC BY-NC-ND`, `CC-BY-NC-ND` and `CCBY-NC-ND` are one code written
        # three ways. The prefix is stripped after the separators collapse, so
        # the spelling without one normalizes too instead of becoming garbage
        # that is silently dropped.
        code = re.sub(r"[\s-]+", "-", match.group(0).strip()).lower()
        codes.add(re.sub(r"^cc-?", "", code))
    return codes


def _grant_is_restricted(text: str) -> bool:
    """Whether the record's own grant forbids commercial use.

    Where the restriction appears is what decides. The Azores records grant
    CC BY and restrict commercial use of the DATA in the same breath, so the
    grant does not hold. The SNIT records forbid commercialising what the SNIT
    PORTAL shows and then grant CC BY over the geographic information itself,
    which is a restriction on the viewer, not on the data -- and CC BY 4.0
    permits commercial use by definition, so reading it the other way would
    make the record contradict itself.

    Read over the record's entries joined together rather than one by one:
    ISO 19115 separates use constraints from other constraints, so a grant and
    the restriction qualifying it routinely arrive as two different strings.
    The check runs whether the code came from a URL or from the text, because
    the Azores wording ends with the CC BY URL.
    """
    return bool(NON_COMMERCIAL_GRANT_RE.search(text))


def license_id_from_legal_constraints(constraints: list[str]) -> str | None:
    """The udata licence id the source grants, or None when it grants none.

    None is not "cc-by by default" -- that constant is the bug this replaces.
    The caller turns it into the portal's default licence.
    """
    text = " ".join(constraints)
    if len(text) > MAX_DECIDABLE_LENGTH:
        # Fail closed: no licence, rather than one read off a prefix.
        return None

    restricted = _grant_is_restricted(text)

    found = set()
    for entry in constraints:
        codes = {code for code in _cc_codes(entry) if code in CC_CODE_TO_LICENSE_ID}
        if len(codes) != 1:
            # Nothing recognisable, or one entry naming two different
            # licences, which grants neither.
            continue
        code = codes.pop()
        if code not in RESTRICTIVE_CC_CODES and restricted:
            continue
        found.add(CC_CODE_TO_LICENSE_ID[code])

    if len(found) == 1:
        return found.pop()
    return None


class DGTBackend(BaseBackend):
    name = "dgt"
    # verify_ssl inherits True from BaseBackend: the configured sources
    # (snig.dgterritorio.gov.pt) present a valid certificate (checked 2026-07).
    display_name = "Harvester DGT"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        import logging

        self.logger = logging.getLogger(__name__)

    @staticmethod
    def _legal_constraints(record: dict) -> list[str]:
        """Normalize the record's `legalConstraints` into a list of strings.

        The GeoNetwork index publishes it as a list for most records and as a
        bare string for some, and omits it entirely for others. Everything
        downstream reads the licence out of these strings, so the shape is
        settled once, here, rather than at every reading.
        """
        constraints = record.get("legalConstraints")
        if isinstance(constraints, str):
            constraints = [constraints]
        elif not isinstance(constraints, list):
            return []

        entries = []
        for entry in constraints[:MAX_CONSTRAINT_ENTRIES]:
            if not isinstance(entry, str):
                continue
            # Sanitized here for the same reason ine.py and inehvd.py sanitize
            # what they put in extras: extras are marshalled raw by the API and
            # copied into the search document, and nothing downstream cleans
            # them -- pre_save only covers title and description.
            entry = sanitize_strict(entry).strip()[:MAX_CONSTRAINT_LENGTH]
            if entry:
                entries.append(entry)
        return entries

    def inner_harvest(self):
        headers = {"content-type": "application/json", "Accept-Charset": "utf-8"}
        # Guarded fetch (SSRF check + retry/timeout) via BaseBackend
        res = self.get(self.source.url, headers=headers)

        res.encoding = "utf-8"
        data = res.json()
        metadata = data.get("metadata")

        # Garante que metadata é sempre uma lista de dicts
        if isinstance(metadata, dict):
            metadata = [metadata]
        elif isinstance(metadata, str) and data.get("@to") == "1":
            # Se for string e @to == "1", não é possível processar como dict, então ignora ou loga erro
            msg = ("Error: metadata é uma string, não um dict: %r", metadata)
            self.logger.error(msg)
            raise Exception(msg)

        elif isinstance(metadata, str) and data.get("@to") == "0":
            msg = "Erro: Metadados vazios. Nenhum dataset disponível."
            self.logger.error(msg)
            raise Exception(msg)

        elif not isinstance(metadata, list):
            metadata = []

        if not metadata:
            msg = "Erro: Metadados vazios. Nenhum dataset disponível."
            self.logger.error(msg)
            raise Exception(msg)

        # Loop through the metadata and process each item
        for each in metadata:
            item = {
                "remote_id": each.get("geonet:info", {}).get("uuid"),
                "title": each.get("defaultTitle"),
                "description": each.get("defaultAbstract"),
                "resources": each.get("link"),
                "keywords": each.get("keyword"),
                "legal_constraints": self._legal_constraints(each),
            }
            # if each.get("publicationDate"):
            #    item["date"] = datetime.strptime(each.get("publicationDate"),
            #                                     "%Y-%m-%d")

            links = []
            resources = item.get("resources")

            # Checks if resources is a list or string and processes accordingly
            if isinstance(resources, list):
                for url in resources:
                    url_parts = url.split("|")
                    inner_link = {}
                    inner_link["url"] = url_parts[2]
                    inner_link["type"] = url_parts[3]
                    inner_link["format"] = url_parts[4]
                    links.append(inner_link)

            elif isinstance(resources, str):
                url_parts = resources.split("|")
                inner_link = {}
                inner_link["url"] = url_parts[2]
                inner_link["type"] = url_parts[3]
                inner_link["format"] = url_parts[4]
                links.append(inner_link)

            item["resources"] = links

            self.process_dataset(item["remote_id"], items=item)

    def inner_process_dataset(self, item: HarvestItem, **kwargs):
        """Process harvested data into a dataset"""
        dataset = self.get_dataset(item.remote_id)
        # Here you comes your implementation. You should :
        # - fetch the remote dataset (if necessary)
        # - validate the fetched payload
        # - map its content to the dataset fields
        # - store extra significant data in the `extra` attribute
        # - map resources data
        data = kwargs.get("items")

        # Set basic dataset fields
        dataset.title = data["title"]
        dataset.license = self._license_for(dataset, item, data)
        dataset.tags = ["snig.dgterritorio.gov.pt"]
        dataset.description = data["description"]

        if data.get("date"):
            dataset.created_at = data["date"]

        # Add keywords as tags
        if data.get("keywords"):
            for keyword in data.get("keywords"):
                dataset.tags.append(keyword)

        # Reconcile the resources with the payload, keeping the id — and hence
        # the download permalink — of the ones already known (LEDG-2251).
        resources = []

        for resource in data.get("resources"):
            resources.append(
                {
                    "title": data["title"],
                    "url": resource["url"],
                    "filetype": "remote",
                    # `type` is the source's protocol and `format` its MIME type;
                    # neither is a `Resource` field, both are only inputs here.
                    "format": format_from_link(
                        resource.get("type"), resource.get("format"), resource["url"]
                    ),
                }
            )

        sync_resources(dataset, resources)

        # Add extra metadata
        dataset.extras["harvest:name"] = self.source.name
        # Kept so the licence decision can be audited without going back to the
        # source. An empty list says the source published nothing, which is not
        # the same as a record harvested before this was read.
        dataset.extras["harvest:legal_constraints"] = data.get("legal_constraints") or []

        return dataset

    def _license_for(self, dataset, item: HarvestItem, data: dict):
        """The licence the source grants, falling back the way CKAN does.

        Source first, then a correction a producer made by hand, then the
        portal default. It never falls back to `cc-by` -- that constant was the
        bug, and `notspecified` is what the portal says when it does not know.

        The middle step is the delicate one. Keeping whatever the dataset
        already carries is what lets a producer's correction survive a harvest,
        but applied blindly it also makes the licence irrevocable: a source that
        stops granting CC BY would never take it back, because the value we
        wrote ourselves last night is indistinguishable from an editorial
        decision. So what this backend derived is recorded, and only a licence
        that differs from it is treated as somebody's correction.
        """
        license_id = license_id_from_legal_constraints(data.get("legal_constraints") or [])
        resolved = License.objects(id=license_id).first() if license_id else None
        if license_id and resolved is None:
            # The portal does not carry this licence yet. Visible on purpose:
            # silently landing on a near neighbour is how a record ends up
            # granting more than its source does.
            self.logger.warning(
                "DGT record %r declares licence %r, which the portal does not have",
                item.remote_id,
                license_id,
            )

        if resolved is not None:
            dataset.extras[DERIVED_LICENSE_EXTRA] = resolved.id
            return resolved

        # The source grants nothing. Anything on the dataset that is not what
        # we last wrote is a correction, and stays.
        current = dataset.license
        if current is not None and current.id != dataset.extras.get(DERIVED_LICENSE_EXTRA):
            dataset.extras.pop(DERIVED_LICENSE_EXTRA, None)
            return current

        # `default` has to be a document: Dataset.license is a ReferenceField
        # and a raw string raises (LEDG-2315).
        default = License.default()
        if default is not None:
            dataset.extras[DERIVED_LICENSE_EXTRA] = default.id
        return default
