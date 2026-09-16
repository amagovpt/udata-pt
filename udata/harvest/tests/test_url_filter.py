import pytest

from ..url_filter import redact_url_credentials, redact_url_credentials_in_url


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


class RedactURLCredentialsInURLTest:
    """`redact_url_credentials_in_url` removes the userinfo of a value that IS a URL.

    Resource URLs and harvest item remote ids are whole URLs, not prose, and
    splitting them is both stricter and safer than the free-text regex can
    afford to be (LEDG-2500).
    """

    @pytest.mark.parametrize(
        "url,expected",
        [
            # The shapes the free-text regex also handles.
            (
                "https://harvestuser:sup3rs3cr3t@transparencia.example.pt/explore/",
                "https://***@transparencia.example.pt/explore/",
            ),
            # An API token used as the username, with no password at all.
            ("https://t0ken@host.pt/x", "https://***@host.pt/x"),
            # A password holding an unencoded `@`: the whole userinfo goes.
            ("https://u:p@ss@host.pt/x", "https://***@host.pt/x"),
            # `udata.uris` accepts a scheme-relative URL, so one can be stored.
            ("//u:p@host.pt/x", "//***@host.pt/x"),
            ("https://u:p@[2001:db8::1]:8080/x", "https://***@[2001:db8::1]:8080/x"),
            # No credentials: unchanged, including a bare host and a real
            # ODS export URL with its query string.
            ("https://transparencia.example.pt", "https://transparencia.example.pt"),
            (
                "https://t.pt/explore/dataset/x/download?format=csv&timezone=Europe/Berlin",
                "https://t.pt/explore/dataset/x/download?format=csv&timezone=Europe/Berlin",
            ),
            # Idempotent: a second pass must not redact the marker again.
            ("https://***@host.pt/x", "https://***@host.pt/x"),
            (None, None),
            ("", ""),
        ],
    )
    def test_userinfo_is_redacted(self, url, expected):
        assert redact_url_credentials_in_url(url) == expected

    @pytest.mark.parametrize(
        "password",
        # Every one of these is accepted by `udata.uris.URL_REGEX`, whose
        # userinfo group is a run of non-space characters, and sent by
        # `requests` as basic
        # auth -- but none is in the RFC 3986 authority alphabet the free-text
        # regex has to stop at. They are common in generated passwords.
        ["S3cr3t{x}", "S3cr3t|x", "S3cr3t^x", "S3cr3t<x>", 'S3"cr3t', "S3`cr3t"],
    )
    def test_a_password_outside_the_authority_alphabet_is_still_redacted(self, password):
        url = f"https://api:{password}@transparencia.example.pt/explore/"

        redacted = redact_url_credentials_in_url(url)

        assert redacted == "https://***@transparencia.example.pt/explore/"
        assert password not in redacted
        # The free-text regex is the one that cannot reach these, which is why
        # a URL-shaped value must not be handed to it.
        assert redact_url_credentials(url) == url

    @pytest.mark.parametrize(
        "url",
        [
            # `//` inside a path, followed by a filename holding `@`. A real
            # URL a publisher may have on a resource, which the free-text
            # regex rewrites into `//***@2026.csv` and destroys.
            "https://host.pt/files//report@2026.csv",
            "https://host.pt/redirect?to=https://a@b.pt",
            "https://host.pt/contact#mail@host.pt",
        ],
    )
    def test_an_at_outside_the_authority_is_left_alone(self, url):
        assert redact_url_credentials_in_url(url) == url
