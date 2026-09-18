import re
from urllib.parse import parse_qs, urlparse

from udata.harvest.backends.base import BaseBackend
from udata.harvest.models import HarvestItem
from udata.models import License

from .tools.harvester_utils import sync_resources

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
# Azores (SRAAC/DRPM) records word it. See `_grant_is_restricted`.
NON_COMMERCIAL_GRANT_RE = re.compile(
    r"(?:usos?|fins)\s+n[\u00e3a]o[\s-]+comerciai?s?|uso\s+comercial\b[^.]*\bproibido",
    re.IGNORECASE,
)

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


def _cc_code(entry: str) -> str | None:
    """The Creative Commons code an entry declares, or None."""
    match = CC_LICENSE_URL_RE.search(entry)
    if match:
        return match.group(1).lower()

    match = CC_LICENSE_CODE_RE.search(entry)
    if match:
        # `CC BY-NC-ND` and `CC-BY-NC-ND` are the same code written differently.
        return re.sub(r"[\s-]+", "-", match.group(0).strip()).lower().removeprefix("cc-")
    return None


def _grant_is_restricted(entry: str) -> bool:
    """Whether the entry's own grant forbids commercial use.

    Where the restriction appears is what decides. The Azores records grant
    CC BY and restrict commercial use of the DATA in the same breath, so the
    grant does not hold. The SNIT records forbid commercialising what the SNIT
    PORTAL shows and then grant CC BY over the geographic information itself,
    which is a restriction on the viewer, not on the data -- and CC BY 4.0
    permits commercial use by definition, so reading it the other way would
    make the record contradict itself.

    The check runs on the entry that produced the code, whether the code came
    from a URL or from the text: the Azores wording ends with the CC BY URL,
    so exempting URLs would let exactly the records this guards against
    through.
    """
    return bool(NON_COMMERCIAL_GRANT_RE.search(entry))


def license_id_from_legal_constraints(constraints: list[str]) -> str | None:
    """The udata licence id the source grants, or None when it grants none.

    None is not "cc-by by default" -- that constant is the bug this replaces.
    The caller turns it into the portal's default licence.
    """
    found = set()
    for entry in constraints:
        code = _cc_code(entry)
        if code is None:
            continue
        if code not in RESTRICTIVE_CC_CODES and _grant_is_restricted(entry):
            continue
        license_id = CC_CODE_TO_LICENSE_ID.get(code)
        if license_id:
            found.add(license_id)

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
        return [entry.strip() for entry in constraints if isinstance(entry, str) and entry.strip()]

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
            parsed = urlparse(resource["url"])
            try:
                format = str(parse_qs(parsed.query)["service"][0])
            except KeyError:
                format = resource["url"].split(".")[-1]

            resources.append(
                {
                    "title": data["title"],
                    "url": resource["url"],
                    "filetype": "remote",
                    "format": format,
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

        Source first, then whatever the dataset already carries, then the
        portal default. The middle step is what lets a producer correct the
        licence in the back office and keep the correction: before this, every
        harvest stamped `cc-by` over it. It never falls back to `cc-by` -- that
        constant was the bug, and `notspecified` is what the portal says when
        it does not know.
        """
        license_id = license_id_from_legal_constraints(data.get("legal_constraints") or [])
        resolved = License.objects(id=license_id).first() if license_id else None
        if license_id and resolved is None:
            # The portal does not carry this licence yet. Visible on purpose:
            # silently landing on a near neighbour is how a record ends up
            # granting more than its source does.
            self.logger.warning(
                "DGT record %s declares licence %r, which the portal does not have",
                item.remote_id,
                license_id,
            )
        # `default` has to be a document: Dataset.license is a ReferenceField
        # and a raw string raises (LEDG-2315).
        return resolved or dataset.license or License.default()
