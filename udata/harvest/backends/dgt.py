import re

from udata.core.dataset.models import HarvestDatasetMetadata
from udata.core.spatial.models import SpatialCoverage
from udata.core.utils.sanitization import sanitize_strict
from udata.harvest.backends.base import BaseBackend
from udata.harvest.models import HarvestItem
from udata.models import License
from udata.utils import safe_harvest_datetime

from .tools.harvester_utils import (
    OGC_SERVICE_FORMATS,
    bbox_to_multipolygon,
    guess_url_format,
    map_iso_maintenance_frequency,
    reset_maintenance_frequency_warnings,
    sync_resources,
)

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

    @staticmethod
    def _parse_link(link: str) -> dict | None:
        """Read one `link` entry, or `None` when it names no resource.

        The index writes each one as `name|description|url|protocol|mime|order`.
        All 733 links of a 400-record sample taken on 2026-09-21 carried the six
        fields, but the previous implementation indexed `[2]`, `[3]` and `[4]`
        with no length check at all, and a single short entry would not have
        failed one item -- it would have raised out of `inner_harvest` and taken
        the whole job down before any record was processed.

        Fields 0 and 1 were never read, which is why every resource ended up
        repeating the title of its dataset. They are filled on a minority of
        links (16.2% and 19.3% of the sample), so the caller keeps the dataset
        title as the fallback.

        A name or description containing a `|` is read from the right instead:
        the four trailing fields are structurally fixed, while the free text is
        the only part that can hold a separator. Reading positionally from the
        left would take the description's own tail as the URL, which
        `URLField` then refuses -- failing the item over a punctuation mark the
        producer typed. No such link was in the 733 sampled, but nothing in the
        format prevents one.
        """
        if not isinstance(link, str):
            return None

        parts = link.split("|")
        if len(parts) > 6:
            # `name|desc with | inside|url|protocol|mime|order`: everything up
            # to the last four fields is the free text, split once.
            head, parts = parts[:-4], parts[-4:]
            name, _, description = "|".join(head).partition("|")
            parts = [name, description] + parts
        else:
            # Pad rather than reject: a shorter entry is still usable if it has
            # a URL.
            parts += [""] * (6 - len(parts))

        url = parts[2].strip()
        if not url:
            return None

        # `title` is sanitized here because `Dataset.pre_save` does not cover it
        # -- it sanitizes the dataset title and both descriptions, and leaves
        # `resource.title` alone. `description` is left as published, so the
        # markdown sanitizer downstream keeps the formatting that a strict
        # sanitizer would strip.
        title = sanitize_strict(parts[0]).strip()
        description = parts[1].strip()
        return {
            "title": title or None,
            "description": description or None,
            "url": url,
            "type": parts[3].strip(),
            "format": parts[4].strip(),
        }

    @staticmethod
    def _geo_boxes(record: dict) -> list[tuple[float, float, float, float]]:
        """The record's bounding boxes, as `(minx, miny, maxx, maxy)` tuples.

        `geoBox` is published as `west|south|east|north` -- checked against the
        LNEG record `20df57a5-76db-4c5e-ae78-45e423e4a88f`, whose
        `-8.13|37.46|-7.77|37.68` places Neves-Corvo where it is. It is filled
        on 99.5% of the index, as a bare string for most records and as a list
        for a few (5 of 400 sampled), which is why several boxes are kept
        rather than the first: a MultiPolygon holds them all.

        Anything that is not four coordinates on Earth is dropped rather
        than guessed at -- including `nan` and `inf`, which `float` reads
        without complaint and which would fail the item at save time.
        """
        value = record.get("geoBox")
        if isinstance(value, str):
            value = [value]
        elif not isinstance(value, list):
            return []

        boxes = []
        for entry in value:
            if not isinstance(entry, str):
                continue
            parts = entry.split("|")
            if len(parts) != 4:
                continue
            try:
                minx, miny, maxx, maxy = (float(part) for part in parts)
            except ValueError:
                continue
            # Geographic coordinates, in degrees. A source publishing
            # projected metres would otherwise put a dataset several thousand
            # degrees off the map, and nothing downstream would reject it --
            # `spatial.geom` carries no 2dsphere index.
            #
            # This is also what rejects `nan` and `inf`, which `float` parses
            # happily: every comparison against NaN is false, so the bounds
            # below refuse it, and the infinities fall outside them. A
            # non-finite corner would otherwise reach `SpatialCoverage.geom`
            # intact and fail the item at save time, where no handler here
            # could catch it.
            if not (-180 <= minx <= 180 and -180 <= maxx <= 180):
                continue
            if not (-90 <= miny <= 90 and -90 <= maxy <= 90):
                continue
            boxes.append((minx, miny, maxx, maxy))
        return boxes

    @staticmethod
    def _update_frequency(record: dict) -> str | None:
        """The record's `updateFrequency`, as the source spells it.

        Filled on 42.4% of the index. Comes as a bare string; a list is
        tolerated for the same reason the dates and the bounding box are, and
        the first entry is taken -- unlike the dates, several frequencies have
        no order to pick from.
        """
        value = record.get("updateFrequency")
        if isinstance(value, list):
            value = next((entry for entry in value if isinstance(entry, str)), None)
        return value if isinstance(value, str) else None

    @staticmethod
    def _publication_dates(record: dict) -> list[list[str]]:
        """The dates the source offers, grouped by field, best field first.

        `publicationDate` is what the index means by it and is filled on 81.2%
        of the records; `referenceDate` is on every one of them and stands in
        for the rest. The groups are kept apart rather than merged -- a
        reference date is not a publication date, and pooling them would let
        the earliest win regardless of which field it came from -- and the
        caller falls through to the next group when a group yields no readable
        date, so a garbage `publicationDate` does not cost a usable
        `referenceDate`.

        Both fields come as a bare string for most records and as a list for a
        few (1 of 400 sampled on 2026-09-21 carried three publication dates).
        """
        groups = []
        for field in ("publicationDate", "referenceDate"):
            value = record.get(field)
            if isinstance(value, str):
                value = [value]
            elif not isinstance(value, list):
                continue
            dates = [entry for entry in value if isinstance(entry, str) and entry.strip()]
            if dates:
                groups.append(dates)
        return groups

    def inner_harvest(self):
        # An unmapped frequency is warned about once per harvest, not once per
        # dataset; without the reset it would be silenced for the lifetime of
        # the Celery worker instead.
        reset_maintenance_frequency_warnings()

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
            item["created_at"] = self._publication_dates(each)
            item["update_frequency"] = self._update_frequency(each)
            item["geo_boxes"] = self._geo_boxes(each)

            # `link` comes as a list for records with several resources and as
            # a bare string for records with one, the same two shapes
            # `_legal_constraints` settles above.
            resources = item.get("resources")
            if isinstance(resources, str):
                resources = [resources]
            elif not isinstance(resources, list):
                resources = []

            links = []
            for link in resources:
                parsed = self._parse_link(link)
                if parsed is None:
                    self.logger.warning(
                        "DGT: skipping a link of %s that names no resource: %r",
                        item["remote_id"],
                        link,
                    )
                    continue
                links.append(parsed)

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

        # `Dataset.created_at` is a read-only property -- it reads
        # `harvest.issued_at or harvest.created_at or created_at_internal` --
        # so the assignment that used to stand here would have raised
        # `AttributeError` for every record carrying a date, had the block in
        # `inner_harvest` that feeds it ever been uncommented. The harvest
        # metadata is what the property reads, and what `rdf.py` writes.
        for group in data.get("created_at") or []:
            published = [
                parsed
                for parsed in (
                    safe_harvest_datetime(value, "DGT publication date", refuse_future=True)
                    for value in group
                )
                if parsed
            ]
            if not published:
                # Nothing readable in this field; try the next one.
                continue
            if not dataset.harvest:
                dataset.harvest = HarvestDatasetMetadata()
            # The earliest of them: a record publishing three dates was first
            # published on the first of the three, not on whichever the index
            # happened to list first.
            dataset.harvest.created_at = min(published)
            break

        # `unknown` when the source says nothing. The field itself has no
        # default and was `None` on these datasets until now; both read as
        # "no frequency given" to `Dataset.has_frequency`, but the API starts
        # serialising `"unknown"` where it served `null`.
        #
        # Written on every harvest, like `ine`, `inehvd`, `maaf` and `odspt`
        # do, so a frequency set by hand in the back office is replaced by what
        # the source says. Deliberate -- the ticket asks for `unknown` when the
        # source is silent -- but it is the one field here without the
        # `DERIVED_LICENSE_EXTRA` style of guard the licence has.
        dataset.frequency = map_iso_maintenance_frequency(data.get("update_frequency"))

        boxes = data.get("geo_boxes")
        if boxes:
            # Replaces the whole coverage: `SpatialCoverage.clean` refuses
            # `zones` and `geom` together, so the two cannot be merged.
            #
            # Not wrapped in a try: `_geo_boxes` has already rejected anything
            # that is not four finite coordinates in range, and what the model
            # would raise for a bad geometry is a mongoengine `ValidationError`
            # at `save()` -- outside any handler that could sit here.
            dataset.spatial = SpatialCoverage(geom=bbox_to_multipolygon(boxes))

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
                    # `ResourceMixin.title` is required, so the dataset title
                    # stays as the fallback for the links that carry no name.
                    "title": resource.get("title") or data["title"],
                    "description": resource.get("description"),
                    "url": resource["url"],
                    "filetype": "remote",
                    # `type` is the source's protocol and `format` its MIME type.
                    # Neither is passed on: `Resource.type` is a closed choice
                    # field (`main`, `api`, ...), and handing it `OGC:WMS` would
                    # fail every item on validation. They are inputs here only.
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
