import logging

from dateutil.parser import parse as parse_dt

from udata import uris
from udata.core.dataset.models import HarvestDatasetMetadata
from udata.core.dataset.rdf import temporal_from_literal
from udata.harvest.backends.base import BaseBackend, HarvestFilter
from udata.harvest.models import HarvestItem
from udata.i18n import gettext as _
from udata.models import License
from udata.mongo.datetime_fields import DateRange

from .tools.harvester_utils import (
    attach_publisher_contact,
    bbox_to_spatial_coverage,
    guess_format_from_mime,
    guess_url_format,
    sync_resources,
)

log = logging.getLogger(__name__)

# The TML source publishes thirteen distributions per collection and the portal
# only catalogues three of them: the two item downloads and the collection
# schema. The labels below are the source's own, matched verbatim (LEDG-2512).
ITEMS_AS_PREFIX = "Items as "
SCHEMA_DISTRIBUTION_LABEL = "Schema of collection in JSON"

# This source publishes its formats in upper case, and two of them are not the
# upper-cased format name: `GeoJSON` and `JSON-LD`. The guess itself is shared
# (`guess_format_from_mime`), so only the spelling is kept here.
FORMAT_LABELS = {"geojson": "GeoJSON", "jsonld": "JSON-LD"}

# How an interval says it has no start or no end. `..` is what OGC API -
# Common writes for an open bound; `None` is what the TML source writes, as the
# Python repr of a missing value.
OPEN_INTERVAL_BOUNDS = frozenset({"", "..", "none", "null"})


class OGCBackend(BaseBackend):
    """
    Harvester backend for OGC API - Collections (JSON format).
    Processes collections from OGC API endpoints and creates datasets with resources.
    """

    name = "ogc"
    display_name = "Harvester OGC"
    filters = (HarvestFilter(_("Tag"), "tags", str, _("A keyword/tag name")),)

    def _item_keywords(self, keywords):
        """Normalize an item's keywords into a lower-cased set of strings."""
        if isinstance(keywords, str):
            keywords = [keywords]
        if not isinstance(keywords, list):
            return set()
        return {kw.strip().lower() for kw in keywords if kw and isinstance(kw, str)}

    def _matches_filters(self, keywords):
        """Apply the configured `tags` filters against an item's keywords.

        Filters are combined with AND semantics: the item is kept only if it
        satisfies every filter. An include filter requires its value to be
        present in the keywords; an exclude filter requires it to be absent.
        Comparison is case-insensitive. Items without keywords never satisfy an
        include filter.
        """
        item_keywords = self._item_keywords(keywords)
        for f in self.get_filters():
            if f.get("key") != "tags":
                continue
            value = (f.get("value") or "").strip().lower()
            if not value:
                continue
            if f.get("type") == "exclude":
                if value in item_keywords:
                    return False
            else:  # include (default)
                if value not in item_keywords:
                    return False
        return True

    def inner_harvest(self):
        """
        Fetches OGC API collections (JSON-LD) and enqueues them for processing.
        """
        headers = {"content-type": "application/json", "Accept-Charset": "utf-8"}

        try:
            # Guarded fetch (SSRF check + retry/timeout) via BaseBackend
            res = self.get(self.source.url, headers=headers)
            res.encoding = "utf-8"
            data = res.json()
        except Exception as e:
            msg = f"Error fetching OGC data: {e}"
            log.error(msg)
            raise Exception(msg)

        # OGC/Schema.org JSON-LD structure: look for 'dataset' array
        metadata = data.get("dataset")

        if not metadata:
            msg = f'Could not find "dataset" in OGC response. Keys found: {list(data.keys())}'
            log.error(msg)
            raise Exception(msg)

        # Ensure metadata is always a list
        if isinstance(metadata, dict):
            metadata = [metadata]

        # Loop through the metadata and process each dataset
        for each in metadata:
            remote_id = each.get("@id")

            if not remote_id:
                log.warning(f"Skipping OGC dataset without @id: {each.get('name')}")
                continue

            keywords = each.get("keywords") or []
            if not self._matches_filters(keywords):
                continue

            item = {
                "remote_id": str(remote_id),
                "title": each.get("name") or "Untitled Dataset",
                "description": each.get("description") or "",
                "keywords": keywords,
                "distributions": each.get("distribution") or [],
                # The catalogue publishes a licence of its own for the
                # collections that carry none, the same way it does `provider`.
                "license": each.get("license") or data.get("license"),
                "temporal_coverage": each.get("temporalCoverage"),
                "url": each.get("url"),
                "spatial_boxes": self._spatial_boxes(each.get("spatial")),
                "provider": each.get("provider") or data.get("provider"),
            }

            self.process_dataset(item["remote_id"], items=item)

    def inner_process_dataset(self, item: HarvestItem, **kwargs):
        """
        Process harvested OGC JSON-LD data into a dataset.
        """
        dataset = self.get_dataset(item.remote_id)
        item_data = kwargs.get("items")

        # Set basic dataset fields
        dataset.title = item_data["title"]
        dataset.description = item_data["description"]
        # The source's own host. The constant that stood here named the DGT OGC
        # API, so every dataset harvested from any other OGC source -- the TML
        # collections, the one source configured -- carried the DGT's tag. The
        # tag list is rebuilt on every run, so the old tag goes on the first
        # harvest. An empty hostname would fail `TagListField` on its minimum
        # length.
        dataset.tags = [self.source.domain] if self.source.domain else []

        # Add keywords as tags
        keywords = item_data.get("keywords", [])
        if isinstance(keywords, list):
            for keyword in keywords:
                if keyword and isinstance(keyword, str):
                    dataset.tags.append(keyword)
        elif isinstance(keywords, str) and keywords:
            dataset.tags.append(keywords)

        # Reconcile the resources with the payload instead of recreating them,
        # which used to give every distribution a new download permalink on
        # every run (LEDG-2251).
        resources = []

        distributions = item_data.get("distributions", [])
        if isinstance(distributions, list):
            for dist in distributions:
                if isinstance(dist, dict):
                    url = dist.get("contentURL", "")
                    if not url:
                        continue

                    # Determine format from encodingFormat
                    link_type = dist.get("encodingFormat", "")

                    # Skip HTML and PNG resources as requested. This has to stay
                    # ahead of the label check: the source also publishes an
                    # "Items as HTML" distribution, which carries the prefix the
                    # check below looks for and would otherwise be catalogued.
                    if link_type in ("text/html", "image/png"):
                        continue

                    label = self._distribution_label(dist)
                    if not self._is_target_distribution(label):
                        continue

                    # The MIME type is authoritative when the source sends one;
                    # only without it is the URL read, which is why the guess is
                    # called without a URL here.
                    if link_type:
                        subtype = link_type.rsplit("/", 1)[-1] if "/" in link_type else link_type
                        fmt = guess_format_from_mime(link_type, fallback=subtype)
                        format_value = FORMAT_LABELS.get(fmt, fmt.upper())
                    else:
                        format_value = guess_url_format(url, fallback="unknown")

                    resource_title = self._resource_title(label, item_data["title"])

                    resources.append(
                        {
                            "title": resource_title,
                            "url": url,
                            "filetype": "remote",
                            "format": format_value,
                        }
                    )

        if distributions and not resources:
            # Nothing matched. The labels are the source's, so an upstream
            # rename empties the dataset rather than failing the item, and the
            # job still reports success -- the one way this change can go wrong
            # without anyone noticing. Say so per item, so the cause is in the
            # log before the missing downloads are reported by a user.
            log.warning(
                "OGC: no distribution of %s matched the catalogued labels; "
                "%d were offered and all were dropped. Labels seen: %s",
                item.remote_id,
                len(distributions),
                sorted(
                    {
                        self._distribution_label(dist)
                        for dist in distributions
                        if isinstance(dist, dict)
                    }
                ),
            )

        sync_resources(dataset, resources)

        # Add extra metadata
        dataset.extras["harvest:name"] = self.source.name

        # License logic
        license_url = item_data.get("license")
        if license_url:
            dataset.license = License.guess(license_url)
        if not dataset.license:
            # Fallback if guess failed or no license provided
            dataset.license = License.guess("notspecified")

        # The collection's own page. Reset first, so a collection that stops
        # announcing one does not keep yesterday's. `remote_url` is a validated
        # `URLField`: an unusable link would raise at `save()` and cost the
        # whole item, so it costs the link instead -- as in `cswudata`.
        if not dataset.harvest:
            dataset.harvest = HarvestDatasetMetadata()
        dataset.harvest.remote_url = None
        url = item_data.get("url")
        if isinstance(url, str) and url.strip():
            try:
                uris.validate(url)
            except uris.ValidationError:
                log.warning(
                    "OGC collection %r announces an unusable url %r",
                    item.remote_id,
                    url[:200],
                )
            else:
                dataset.harvest.remote_url = url.strip()

        # Replaces the whole coverage when the source publishes one, and leaves
        # it alone otherwise: `SpatialCoverage.clean` refuses `zones` and
        # `geom` together, so the two cannot be merged.
        spatial = bbox_to_spatial_coverage(item_data.get("spatial_boxes") or [])
        if spatial:
            dataset.spatial = spatial

        # Only set when it parses, so a coverage entered by hand is not
        # replaced with nothing by a source that publishes none.
        coverage = self._temporal_coverage(item_data.get("temporal_coverage"))
        if coverage:
            dataset.temporal_coverage = coverage
        # The raw text used to be kept here instead. `get_dataset` reuses the
        # stored extras, so without the `pop` every TML dataset already
        # harvested would keep its `"None/None"`; nothing reads the key.
        dataset.extras.pop("temporal_coverage", None)

        # Provider/Publisher
        provider = item_data.get("provider")
        if provider and isinstance(provider, dict):
            dataset.extras["publisher_name"] = provider.get("name")
            dataset.extras["publisher_email"] = provider.get("contactPoint", {}).get("email")

            email = provider.get("contactPoint", {}).get("email") or provider.get("email")
            attach_publisher_contact(self, dataset, provider.get("name"), email)

        return dataset

    @staticmethod
    def _spatial_boxes(spatial) -> list[tuple[float, float, float, float]]:
        """The collection's bounding boxes, as `(minx, miny, maxx, maxy)` tuples.

        schema.org puts them in `spatial[].geo.box`, a `GeoShape` written as two
        space-separated corners. The standard orders each corner `lat,lon`; the
        TML source writes `lon,lat` -- its `-9.4972,38.4194 -8.4575,39.0792`
        only lands on Lisbon in that order -- and it is the one OGC source
        configured, so that is the order read. A source following the standard
        for Portugal would still pass the range check, only transposed.

        Anything else is skipped rather than guessed at; the shared helper then
        drops what is not geographic.
        """
        if isinstance(spatial, dict):
            spatial = [spatial]
        elif not isinstance(spatial, list):
            return []

        boxes = []
        for place in spatial:
            geo = place.get("geo") if isinstance(place, dict) else None
            box = geo.get("box") if isinstance(geo, dict) else None
            if not isinstance(box, str):
                continue
            corners = box.split()
            if len(corners) != 2:
                continue
            try:
                (minx, miny), (maxx, maxy) = (
                    tuple(float(value) for value in corner.split(",")) for corner in corners
                )
            except ValueError:
                continue
            boxes.append((minx, miny, maxx, maxy))
        return boxes

    @staticmethod
    def _temporal_coverage(text) -> DateRange | None:
        """The collection's `temporalCoverage`, or `None` when it names no dates.

        schema.org writes it as an ISO 8601 interval, `start/end`. Either bound
        may be open, and the TML source writes both open as `None/None` on
        every collection, which is no coverage at all. Anything else --
        a single year or month -- goes through `temporal_from_literal`, the
        parser the DCAT path uses.

        Never raises: a coverage that does not parse must not fail the item.
        """
        if not isinstance(text, str) or not text.strip():
            return None
        text = text.strip()
        try:
            if text.count("/") == 1:
                start, end = (
                    None if bound.strip().casefold() in OPEN_INTERVAL_BOUNDS else bound.strip()
                    for bound in text.split("/")
                )
                if not (start or end):
                    return None
                return DateRange(
                    start=parse_dt(start).date() if start else None,
                    end=parse_dt(end).date() if end else None,
                )
            return temporal_from_literal(text)
        except (ValueError, OverflowError):
            log.warning("OGC: unreadable temporalCoverage %r", text[:200])
            return None

    def _distribution_label(self, dist: dict) -> str:
        """The human label a distribution carries, as the resource title reads it.

        The title has always preferred `description` over `name`; the selection
        below reads the very same value, so a distribution can never be kept
        under one label and catalogued under another. That matters more than it
        looks: the TML source leaves `name` unset on every one of its
        distributions and puts the label in `description`, so a check written
        against `name` alone would silently match nothing and leave every
        harvested dataset without resources.

        A non-string `description` - JSON-LD may carry an object there - is
        treated as absent rather than allowed to raise.
        """
        for value in (dist.get("description"), dist.get("name")):
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    def _resource_title(self, label: str, dataset_title: str) -> str:
        """The title a catalogued distribution is published under.

        The source names its two item downloads after itself - "Items as
        GeoJSON" - which says nothing about the data once the resource is read
        outside the collection it came from. They are renamed after the dataset
        instead, so "Items as GeoJSON" on "Rede Ciclável" reads "Rede Ciclável
        como GeoJSON" (LEDG-2512). Every other label, the collection schema
        included, is published exactly as the source wrote it.
        """
        if label.startswith(ITEMS_AS_PREFIX):
            return f"{dataset_title} como {label[len(ITEMS_AS_PREFIX) :]}"
        return label or "Resource"

    def _is_target_distribution(self, label: str) -> bool:
        """Whether a distribution is one of the three the portal catalogues."""
        return label.startswith(ITEMS_AS_PREFIX) or label == SCHEMA_DISTRIBUTION_LABEL
