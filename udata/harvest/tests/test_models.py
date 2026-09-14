import logging

from udata.tests.api import PytestOnlyDBTestCase
from udata.utils import faker

from ..models import HarvestSource

log = logging.getLogger(__name__)


class HarvestSourceTest(PytestOnlyDBTestCase):
    def test_defaults(self):
        source = HarvestSource.objects.create(name="Test", url=faker.url(), backend="factory")
        assert source.name == "Test"
        assert source.slug == "test"

    def test_domain(self):
        source = HarvestSource(name="Test", url="http://www.somewhere.com/path/")
        assert source.domain == "www.somewhere.com"

        source = HarvestSource(name="Test", url="https://www.somewhere.com/path/")
        assert source.domain == "www.somewhere.com"

        source = HarvestSource(name="Test", url="http://www.somewhere.com:666/path/")
        assert source.domain == "www.somewhere.com"

    def test_domain_ignores_url_credentials(self):
        """The userinfo prefix is not the host, and must not be read as one.

        `URLS_ALLOW_CREDENTIALS` lets a URL like this through form validation,
        so the only thing standing between it and a source claiming a domain it
        does not control is this property. Reading the netloc gave the attacker
        the first of these three answers.
        """
        source = HarvestSource(name="Test", url="https://www.ine.pt:1@attacker.example.com/c.xml")
        assert source.domain == "attacker.example.com"

        source = HarvestSource(name="Test", url="https://user:pass@www.somewhere.com/path/")
        assert source.domain == "www.somewhere.com"

        source = HarvestSource(name="Test", url="https://user@www.somewhere.com:666/path/")
        assert source.domain == "www.somewhere.com"

    def test_domain_normalizes_host_and_ipv6(self):
        source = HarvestSource(name="Test", url="https://WWW.SOMEWHERE.COM/path/")
        assert source.domain == "www.somewhere.com"

        source = HarvestSource(name="Test", url="http://[::1]:8080/")
        assert source.domain == "::1"

        source = HarvestSource(name="Test", url="not-a-url")
        assert source.domain == ""
