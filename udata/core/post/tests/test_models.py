import mongoengine
import pytest

from udata.core.pages.factories import PageFactory
from udata.core.pages.models import Page
from udata.core.post.factories import PostFactory
from udata.tests.api import PytestOnlyDBTestCase


class PostTest(PytestOnlyDBTestCase):
    def test_page_deletion_raises_if_reference_still_exists(self):
        page = PageFactory()
        post = PostFactory(body_type="blocs", content_as_page=page)

        # `len(list(...))` rather than `.count()`: mongoengine routes an *unfiltered*
        # count to `estimated_document_count()`, which reads collection metadata and
        # can be wrong in either direction -- including reporting zero while a document
        # that should have been removed is still there.
        assert len(list(Page.objects())) == 1

        with pytest.raises(mongoengine.errors.OperationError):
            page.delete()

        # Delete the post referencing the page before being able to delete the page itself
        post.delete()
        page.delete()

        assert Page.objects(id=page.id).count() == 0
        assert len(list(Page.objects())) == 0
