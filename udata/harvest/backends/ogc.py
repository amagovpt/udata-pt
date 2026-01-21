from udata.harvest.backends.base import BaseBackend
from udata.models import Resource, License, SpatialCoverage
from udata.core.contact_point.models import ContactPoint
from udata.harvest.models import HarvestItem
import requests
import logging

from .tools.harvester_utils import normalize_url_slashes


class OGCBackend(BaseBackend):
    """
    Harvester backend for OGC API - Collections (JSON format).
    Processes collections from OGC API endpoints and creates datasets with resources.
    """
    name = "ogc"
    display_name = 'Harvester OGC'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = logging.getLogger(__name__)

    def inner_harvest(self):
        """
        Fetches OGC API collections (JSON-LD) and enqueues them for processing.
        """
        headers = {
            'content-type': 'application/json',
            'Accept-Charset': 'utf-8'
        }
        
        try:
            res = requests.get(self.source.url, headers=headers)
            res.encoding = 'utf-8'
            data = res.json()
        except Exception as e:
            msg = f'Error fetching OGC data: {e}'
            self.logger.error(msg)
            raise Exception(msg)

        # OGC/Schema.org JSON-LD structure: look for 'dataset' array
        metadata = data.get("dataset")

        if not metadata:
            msg = f'Could not find "dataset" in OGC response. Keys found: {list(data.keys())}'
            self.logger.error(msg)
            raise Exception(msg)

        # Ensure metadata is always a list
        if isinstance(metadata, dict):
            metadata = [metadata]

        # Loop through the metadata and process each dataset
        for each in metadata:
            remote_id = each.get("@id")
            
            if not remote_id:
                self.logger.warning(f"Skipping OGC dataset without @id: {each.get('name')}")
                continue

            item = {
                "remote_id": str(remote_id),
                "title": each.get("name") or "Untitled Dataset",
                "description": each.get("description") or "",
                "keywords": each.get("keywords") or [],
                "distributions": each.get("distribution") or [],
                "license": each.get("license"),
                "temporal_coverage": each.get("temporalCoverage"),
                "provider": each.get("provider") or data.get("provider"),
            }

            self.process_dataset(item["remote_id"], items=item)

    def inner_process_dataset(self, item: HarvestItem, **kwargs):
        """
        Process harvested OGC JSON-LD data into a dataset.
        """
        dataset = self.get_dataset(item.remote_id)
        item_data = kwargs.get('items')

        # Set basic dataset fields
        dataset.title = item_data['title']
        dataset.description = item_data['description']
        dataset.tags = ["ogcapi.dgterritorio.gov.pt"]

        # Add keywords as tags
        keywords = item_data.get('keywords', [])
        if isinstance(keywords, list):
            for keyword in keywords:
                if keyword and isinstance(keyword, str):
                    dataset.tags.append(keyword)
        elif isinstance(keywords, str) and keywords:
            dataset.tags.append(keywords)

        # Recreate all resources
        dataset.resources = []

        distributions = item_data.get("distributions", [])
        if isinstance(distributions, list):
            for dist in distributions:
                if isinstance(dist, dict):
                    url = dist.get("contentURL", "")
                    if not url:
                        continue
                    
                    # Determine format from encodingFormat
                    link_type = dist.get("encodingFormat", "")

                    # Skip HTML and PNG resources as requested
                    if link_type in ('text/html', 'image/png'):
                        continue
                    
                    # Extract format from MIME type or use the type directly
                    if link_type:
                        format_value = self._extract_format_from_mime(link_type)
                    else:
                        # Try to extract from URL
                        format_value = url.split('.')[-1] if '.' in url.split('/')[-1] else "unknown"
                    
                    # Use link title or create a descriptive title
                    resource_title = dist.get("description") or dist.get("name") or "Resource"

                    new_resource = Resource(
                        title=resource_title,
                        url=normalize_url_slashes(url),
                        filetype='remote',
                        format=format_value
                    )
                    dataset.resources.append(new_resource)

        # Add extra metadata
        dataset.extras['harvest:name'] = self.source.name
        
        # License logic
        license_url = item_data.get('license')
        if license_url:
            dataset.license = License.guess(license_url)
        if not dataset.license:
            # Fallback if guess failed or no license provided
            dataset.license = License.guess('notspecified')

        # Temporal Coverage
        temporal = item_data.get('temporal_coverage')
        if temporal:
            dataset.extras['temporal_coverage'] = temporal

        # Provider/Publisher
        provider = item_data.get('provider')
        if provider and isinstance(provider, dict):
            dataset.extras['publisher_name'] = provider.get('name')
            dataset.extras['publisher_email'] = provider.get('contactPoint', {}).get('email')

            # Create contact point
            name = provider.get('name')
            email = provider.get('contactPoint', {}).get('email') or provider.get('email')
            if email:
                email = email.replace('mailto:', '').strip()

            if name or email:
                org_or_owner = {}
                if dataset.organization:
                    org_or_owner = {"organization": dataset.organization}
                elif dataset.owner:
                    org_or_owner = {"owner": dataset.owner}

                if org_or_owner:
                    contact, _ = ContactPoint.objects.get_or_create(
                        name=name,
                        email=email,
                        role='publisher',
                        **org_or_owner
                    )

                    if not dataset.contact_points:
                        dataset.contact_points = []
                    
                    if contact not in dataset.contact_points:
                        dataset.contact_points.append(contact)

        return dataset

    def _extract_format_from_mime(self, mime_type: str) -> str:
        """
        Extract a simple format string from a MIME type.
        """
        mime_to_format = {
            'application/json': 'JSON',
            'application/ld+json': 'JSON-LD',
            'application/xml': 'XML',
            'application/xls': 'XLS',
            'application/xlsx': 'XLSX',
            'application/csv': 'CSV',
            'text/csv': 'CSV',
            'text/xml': 'XML',
            'application/geo+json': 'GeoJSON',
            'application/gml+xml': 'GML',
        }
        return mime_to_format.get(mime_type, mime_type.split('/')[-1].upper() if '/' in mime_type else mime_type)