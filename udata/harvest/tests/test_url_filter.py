import pytest

from ..url_filter import redact_url_credentials


class RedactURLCredentialsTest:
    """`redact_url_credentials` removes the userinfo of every URL in free text.

    A harvest source URL may legitimately carry `user:password@` because
    `URLS_ALLOW_CREDENTIALS` is true, and anything derived from it is served
    to callers without a session (LEDG-2477).
    """

    @pytest.mark.parametrize(
        "text,expected",
        [
            # The proof of concept from the ticket: the password reached the
            # API through the text of a `requests` exception.
            (
                "500 Server Error: None for url: "
                "https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml",
                "500 Server Error: None for url: https://***@www.ine.pt/broken.xml",
            ),
            # A username on its own is a secret too: plenty of services pass an
            # API token as the basic-auth user.
            ("https://s3cr3t-token@api.example.com/feed", "https://***@api.example.com/feed"),
            # An unencoded `@` inside the password: the greedy match must take
            # the last one, not the first.
            ("https://user:p@ss@data.example.com/x", "https://***@data.example.com/x"),
            ("https://user:p%40ss@data.example.com/x", "https://***@data.example.com/x"),
            ("HTTPS://USER:PASS@DATA.EXAMPLE.COM/x", "HTTPS://***@DATA.EXAMPLE.COM/x"),
            # Two URLs in one message must not be collapsed into one match.
            (
                "tried https://u1:p1@a.example.com/x then https://u2:p2@b.example.com/y",
                "tried https://***@a.example.com/x then https://***@b.example.com/y",
            ),
            # Nothing to redact: these must come back byte for byte.
            ("https://www.ine.pt/broken.xml", "https://www.ine.pt/broken.xml"),
            ("write to admin@example.com for access", "write to admin@example.com for access"),
            (
                "https://example.com/search?contact=admin@example.com",
                "https://example.com/search?contact=admin@example.com",
            ),
            (
                "HTTPSConnectionPool(host='example.com', port=443)",
                "HTTPSConnectionPool(host='example.com', port=443)",
            ),
            ("", ""),
            (None, None),
        ],
    )
    def test_redacts_userinfo(self, text, expected):
        assert redact_url_credentials(text) == expected

    def test_is_idempotent(self):
        """Running it twice must not eat the `***@` marker it just wrote.

        The migration re-selects documents on a pattern that also matches an
        already redacted URL, so a second run has to be a no-op in content.
        """
        once = redact_url_credentials(
            "500 Server Error for url: https://harvestuser:sup3rs3cr3t@www.ine.pt/broken.xml"
        )
        assert redact_url_credentials(once) == once

    def test_does_not_backtrack_catastrophically(self):
        """A long message without a match must not hang the save path."""
        text = "https://" + "a" * 20000 + "/x"
        assert redact_url_credentials(text) == text
