from datetime import datetime, timedelta
from urllib.parse import quote_plus

from flask import current_app, url_for
from flask_security.utils import hash_data

from udata.core.user.factories import AdminFactory, UserFactory
from udata.tests.api import APITestCase
from udata.tests.helpers import capture_mails


class AuthTest(APITestCase):
    def test_change_mail(self):
        user = self.login(AdminFactory())

        new_email = "test@test.com"

        security = current_app.extensions["security"]

        data = [str(user.fs_uniquifier), hash_data(user.email), new_email]
        token = security.confirm_serializer.dumps(data)
        confirmation_link = url_for("security.confirm_change_email", token=token)

        resp = self.get(confirmation_link)
        assert resp.status_code == 302

        user.reload()
        assert user.email == new_email

    def test_change_mail_already_taken(self):
        """Should not allow changing email to one already taken by another user"""
        user = self.login(AdminFactory())
        original_email = user.email

        # Create another user with the target email
        existing_user = UserFactory(email="taken@example.com")
        new_email = existing_user.email

        security = current_app.extensions["security"]

        data = [str(user.fs_uniquifier), hash_data(user.email), new_email]
        token = security.confirm_serializer.dumps(data)
        confirmation_link = url_for("security.confirm_change_email", token=token)

        resp = self.get(confirmation_link)
        assert resp.status_code == 302
        assert "change_email_already_taken" in resp.location

        # Email should not have changed
        user.reload()
        assert user.email == original_email

    def test_change_mail_after_password_change(self):
        """Changing password rotates fs_uniquifier and invalidates email change token"""
        user = UserFactory(password="Password123!@#")
        self.login(user)
        old_uniquifier = user.fs_uniquifier

        new_email = "new@example.com"

        security = current_app.extensions["security"]

        data = [str(user.fs_uniquifier), hash_data(user.email), new_email]
        token = security.confirm_serializer.dumps(data)
        confirmation_link = url_for("security.confirm_change_email", token=token)

        # Change password via API
        resp = self.post(
            url_for("security.change_password"),
            {
                "password": "Password123!@#",
                "new_password": "NewPassword456!@#",
                "new_password_confirm": "NewPassword456!@#",
                "submit": True,
            },
        )
        assert resp.status_code == 200, f"Password change failed: {resp.data}"

        user.reload()
        assert user.fs_uniquifier != old_uniquifier, "fs_uniquifier should have changed"

        # Now try to use the email change link - should fail
        resp = self.get(confirmation_link)
        assert resp.status_code == 302
        assert "change_email_invalid" in resp.location

    def test_change_mail_from_placeholder_saml_user(self):
        """A password-less CMD/SAML account with a placeholder email can
        complete registration through the change-email flow: submit a real
        email, receive the confirmation link, and have the email replaced."""
        user = UserFactory(email="saml-abcdef01@autenticacao.gov.pt", password=None)
        self.login(user)
        assert user.has_placeholder_email

        new_email = "real.email@example.com"

        with capture_mails() as mails:
            resp = self.post(
                url_for("security.change_email"),
                {
                    "new_email": new_email,
                    "new_email_confirm": new_email,
                    "submit": True,
                },
            )
        assert resp.status_code == 200
        assert len(mails) == 1
        assert mails[0].recipients == [new_email]

        # Extract the confirmation link from the mail and follow it.
        security = current_app.extensions["security"]
        data = [str(user.fs_uniquifier), hash_data(user.email), new_email]
        token = security.confirm_serializer.dumps(data)
        confirmation_link = url_for("security.confirm_change_email", token=token)

        resp = self.get(confirmation_link)
        assert resp.status_code == 302
        assert "change_email_confirmed" in resp.location

        user.reload()
        assert user.email == new_email
        assert not user.has_placeholder_email

    def _submit_change_email(self, address):
        # Form-encoded POST: this is the shape the frontend proxy sends, and
        # the only one whose failure path used to render the error back.
        return self.post(
            url_for("security.change_email"),
            {"new_email": address, "new_email_confirm": address, "submit": True},
            json=False,
        )

    def test_change_mail_rejects_a_padded_address(self):
        """A padded address never reaches the taken/free decision at all.

        udata's StringField has no strip filter, so the submitted value arrives
        with its whitespace -- but validators.Email() refuses it inside
        super().validate(), before the form's own checks and before the view.
        That is why the strip in the view is defence rather than the check.

        Worth pinning: if the email validator ever became lenient about
        surrounding whitespace, that strip would silently become the only thing
        between "taken@example.org " and a confirmation link for someone else's
        address, since confirm_change_email also matches exactly. This test
        fails the moment that assumption stops holding.
        """
        user = self.login(UserFactory(email="saml-deadbeef@autenticacao.gov.pt", password=None))
        UserFactory(email="taken@example.org")

        with capture_mails() as mails:
            resp = self._submit_change_email("  taken@example.org  ")

        # Refused outright: no mail to anyone, and nothing moves. Note this is
        # not an oracle -- a padded free address is refused identically,
        # because the refusal is about the format, not about existence.
        assert len(mails) == 0
        assert resp.status_code == 200

        user.reload()
        assert user.email == "saml-deadbeef@autenticacao.gov.pt"

    def test_change_mail_taken_address_warns_the_owner_at_submit(self):
        """The collision is still handled at submit time, not only after the
        confirmation link is clicked.

        What changed is who is told: the owner of the address, by mail, and not
        whoever submitted it. The previous version of this test asserted the
        opposite -- 200 with "already registered" in the body -- which is the
        disclosure this replaces.
        """
        user = self.login(UserFactory(email="saml-deadbeef@autenticacao.gov.pt", password=None))
        owner = UserFactory(email="taken@example.com")

        with capture_mails() as mails:
            resp = self._submit_change_email("taken@example.com")

        # Exactly one mail, to the mailbox that already holds the address.
        # Never to the requester, who must learn nothing.
        assert len(mails) == 1
        assert mails[0].recipients == [owner.email]

        # No confirmation link was issued for an address this session has
        # proved nothing about.
        assert "confirm-change-email" not in mails[0].body

        # Neither account moves. This is the assertion that stops an account
        # being claimed by naming its address, and it is the one the previous
        # version of this test got right.
        user.reload()
        assert user.email == "saml-deadbeef@autenticacao.gov.pt"
        owner.reload()
        assert owner.email == "taken@example.com"

        # Answered in the success shape; pinned against a free address below.
        assert resp.status_code == 302

    def test_change_mail_taken_address_mails_association_link_to_placeholder_requester(self):
        """The one case where a taken address is the destination, not a mistake.

        A citizen signed in with the CMD, was given a placeholder account, and
        typed the address of the account they already had. The sibling test
        above pins what happens to everybody else: a silent notice with no
        link. Here the owner is mailed an ASSOCIATION link instead -- which is
        the difference between being stuck on the completion screen forever and
        getting back into your own account.

        The two requesters differ by exactly one thing: this one holds a linked
        identity. That is what there is to move; the other has nothing, which
        is why it still falls through to the notice.

        What the CALLER sees is pinned separately, by the indistinguishability
        test below and by the enumeration regression class. Nothing here may be
        read as the caller learning anything.
        """
        from udata.auth.saml.saml_plugin.saml_govpt import (
            MAX_MIGRATION_LINK_SENDS,
            MIGRATION_LINK_ORIGIN,
            MIGRATION_LINK_ORIGIN_REGISTRATION,
            MIGRATION_LINK_PENDING,
            MIGRATION_LINK_PLACEHOLDER_ID,
            MIGRATION_LINK_SEND_COUNT,
            _hash_nic,
        )

        requester = self.login(
            UserFactory(
                email="saml-deadbeef@autenticacao.gov.pt",
                password=None,
                extras={"auth_nic": _hash_nic("12345678")},
                first_name="Pedro",
                last_name="Nunes",
            )
        )
        owner = UserFactory(email="taken@example.com")

        with capture_mails() as mails:
            resp = self._submit_change_email("taken@example.com")

        # Still exactly one mail, still only to the mailbox that holds the
        # address. The requester is told nothing, as in every other branch.
        assert len(mails) == 1
        assert mails[0].recipients == [owner.email]

        # An association link, not a change-email confirmation: it grants this
        # session nothing and acts only when the owner opens it.
        assert "/saml/migration/confirm-link/" in mails[0].body
        assert "confirm-change-email" not in mails[0].body

        owner.reload()
        record = owner.extras[MIGRATION_LINK_PENDING]
        # The identity to move is the requester's, and the record names the
        # placeholder to retire -- the click has no session to read either from.
        assert record["nic_hash"] == _hash_nic("12345678")
        assert record[MIGRATION_LINK_ORIGIN] == MIGRATION_LINK_ORIGIN_REGISTRATION
        assert record[MIGRATION_LINK_PLACEHOLDER_ID] == str(requester.id)

        # Emitting a link moves nothing by itself. Both accounts are exactly
        # where they were until somebody proves the mailbox.
        requester.reload()
        assert requester.email == "saml-deadbeef@autenticacao.gov.pt"
        assert owner.email == "taken@example.com"
        assert not (owner.extras or {}).get("auth_nic")

        assert resp.status_code == 302

        # --- and now the refusals, which must all land on the silent notice ---

        # A target that already holds an identity is somebody else's account.
        linked = UserFactory(email="linked@example.com", extras={"auth_nic": _hash_nic("87654321")})
        with capture_mails() as mails:
            self._submit_change_email("linked@example.com")
        assert len(mails) == 1
        assert "/saml/migration/confirm-link/" not in mails[0].body
        linked.reload()
        assert MIGRATION_LINK_PENDING not in (linked.extras or {})

        # A live link belonging to another flow is not overwritten. Issuing
        # mints a fresh nonce over whatever was there, so without this guard
        # submitting addresses in a loop would void the outstanding link of
        # every owner it touched.
        busy = UserFactory(email="busy@example.com")
        busy.extras = {
            MIGRATION_LINK_PENDING: {
                "nonce": "irrelevant",
                "nic_hash": _hash_nic("11112222"),
                "expires": (datetime.utcnow() + timedelta(minutes=20)).isoformat(),
            }
        }
        busy.save()
        with capture_mails() as mails:
            self._submit_change_email("busy@example.com")
        assert len(mails) == 1
        assert "/saml/migration/confirm-link/" not in mails[0].body
        busy.reload()
        assert busy.extras[MIGRATION_LINK_PENDING]["nonce"] == "irrelevant"

        # The per-target cap. Reachable only once the previous record is gone
        # -- while one is live the guard above refuses first -- so the tally is
        # seeded rather than driven through six submissions that the live-link
        # guard would refuse anyway. This is the ceiling that matters when the
        # links are being consumed or left to expire, which is the only way a
        # typed address can be mailed repeatedly.
        capped = UserFactory(email="capped@example.com")
        capped.extras = {
            MIGRATION_LINK_SEND_COUNT: {
                "count": MAX_MIGRATION_LINK_SENDS,
                "window_start": datetime.utcnow().isoformat(),
            }
        }
        capped.save()
        with capture_mails() as mails:
            self._submit_change_email("capped@example.com")
        assert len(mails) == 1
        assert "/saml/migration/confirm-link/" not in mails[0].body
        capped.reload()
        assert MIGRATION_LINK_PENDING not in (capped.extras or {})

        # A requester with no linked identity has nothing to move. Without this
        # guard the record would be written with nic_hash=None -- a link that
        # opens a session and binds no identity at all.
        self.login(UserFactory(email="saml-cafebabe@autenticacao.gov.pt", password=None))
        untethered = UserFactory(email="untethered@example.com")
        with capture_mails() as mails:
            self._submit_change_email("untethered@example.com")
        assert len(mails) == 1
        assert "/saml/migration/confirm-link/" not in mails[0].body
        untethered.reload()
        assert MIGRATION_LINK_PENDING not in (untethered.extras or {})

    def test_change_mail_taken_address_refuses_association_when_placeholder_owns_content(self):
        """The temporary account already holds work, so nothing is linked.

        Linking retires the temporary account, and retiring it would destroy
        what it holds. The product decision was to refuse rather than move
        content between accounts, so the owner is told -- by a mail that says
        what happened and what to do, not the generic notice whose only advice
        is to sign in, which this citizen cannot do.

        The dataset here stands for the whole list: a pending account holds a
        live session from the assertion onward and the screen that holds it is
        enforced in the browser, so owning something before finishing is
        ordinary.
        """
        from udata.auth.saml.saml_plugin.saml_govpt import (
            MIGRATION_LINK_PENDING,
            _hash_nic,
        )
        from udata.core.dataset.factories import DatasetFactory

        requester = self.login(
            UserFactory(
                email="saml-deadbeef@autenticacao.gov.pt",
                password=None,
                extras={"auth_nic": _hash_nic("12345678")},
            )
        )
        owner = UserFactory(email="taken@example.com")
        DatasetFactory(owner=requester)

        with capture_mails() as mails:
            resp = self._submit_change_email("taken@example.com")

        # Still one mail, still only to the address's owner.
        assert len(mails) == 1
        assert mails[0].recipients == [owner.email]

        # The refusal notice, not the association link and not the generic
        # "sign in as you normally do" notice.
        assert "/saml/migration/confirm-link/" not in mails[0].body
        assert "could not be linked" in mails[0].subject

        # Nothing was written anywhere. No link to click, no identity moved.
        owner.reload()
        assert MIGRATION_LINK_PENDING not in (owner.extras or {})
        assert not (owner.extras or {}).get("auth_nic")
        requester.reload()
        assert requester.extras["auth_nic"] == _hash_nic("12345678")
        assert requester.email == "saml-deadbeef@autenticacao.gov.pt"

        # And the caller is answered exactly as every other branch answers.
        assert resp.status_code == 302

    def test_change_mail_taken_address_answers_like_a_free_one(self):
        """The taken and free branches must be indistinguishable to the caller.

        If they differ in any observable way, one account is enough to test
        any address, which is the enumeration oracle this flow must not be.
        """
        self.login(UserFactory(email="saml-deadbeef@autenticacao.gov.pt", password=None))
        UserFactory(email="taken@example.com")

        taken = self._submit_change_email("taken@example.com")
        free = self._submit_change_email("free@example.com")

        assert taken.status_code == free.status_code

        # The redirect echoes the submitted address, which discloses nothing
        # because the caller chose it -- so normalise it out and require
        # everything else to match byte for byte.
        #
        # Both encodings are normalised: homepage_url goes through cdata_url
        # (urlencode, so "@" becomes %40) when CDATA_BASE_URL is set, and falls
        # back to url_for otherwise, which leaves "@" literal. Normalising only
        # one of them silently turns this into a no-op comparison.
        def normalise(location, address):
            return location.replace(quote_plus(address), "ADDR").replace(address, "ADDR")

        assert normalise(taken.location, "taken@example.com") == normalise(
            free.location, "free@example.com"
        )

    def test_change_mail_same_address_error_is_translated(self):
        """The form's own error must not reach a Portuguese user in English.

        The language comes from the signed-in user: i18n.get_locale reads
        `default_lang`, which is `prefered_language` before it is the configured
        default -- and this suite's default is fr (settings.Testing), not pt.
        The security views are not locale-prefixed, so passing lang_code to
        url_for only appends a query parameter and changes nothing.
        """
        user = self.login(
            UserFactory(email="mine@example.com", password=None, prefered_language="pt")
        )

        resp = self.post(
            url_for("security.change_email"),
            {
                "new_email": user.email,
                "new_email_confirm": user.email,
                "submit": True,
            },
            json=False,
        )

        assert resp.status_code == 200
        body = resp.data.decode()
        assert "must be different than your previous email" not in body
        assert "tem de ser diferente do anterior" in body

    def test_change_mail_case_variant_of_taken_address_answers_like_a_free_one(self):
        """A spelling that differs only in case is the SAME mailbox.

        This widens what counts as taken, which is the whole point -- and a
        widening is exactly where an oracle gets reintroduced by accident. So
        this asserts the same thing as
        test_change_mail_taken_address_answers_like_a_free_one, with the same
        discipline: same-length addresses, and everything but the echoed
        address compared byte for byte.

        ⚠️ The casing varies in the LOCAL part on purpose. The email validator
        lowercases the domain, so a test that only varied the domain would pass
        with and without the fix.
        """
        self.login(UserFactory(email="saml-deadbeef@autenticacao.gov.pt", password=None))
        UserFactory(email="Maria@example.com")

        variant = self._submit_change_email("maria@example.com")
        free = self._submit_change_email("mirta@example.com")

        assert variant.status_code == free.status_code

        def normalise(location, address):
            return location.replace(quote_plus(address), "ADDR").replace(address, "ADDR")

        assert normalise(variant.location, "maria@example.com") == normalise(
            free.location, "mirta@example.com"
        )

    def test_change_mail_case_variant_of_taken_address_issues_no_link(self):
        """The refusal has to be real, not only indistinguishable.

        The test above proves the caller cannot tell the branches apart; this
        one proves the taken branch is the one that ran -- the owner of the
        address is warned and no confirmation link is minted for the caller.
        """
        caller = self.login(UserFactory(email="saml-deadbeef@autenticacao.gov.pt", password=None))
        owner = UserFactory(email="Maria@example.com")

        with capture_mails() as mails:
            self._submit_change_email("maria@example.com")

        assert len(mails) == 1
        assert mails[0].recipients == [owner.email]

        caller.reload()
        assert caller.email == "saml-deadbeef@autenticacao.gov.pt"

    def test_confirm_change_mail_refuses_a_case_variant_taken_after_the_link_was_sent(self):
        """The guard that actually stops the duplicate row being written.

        change_email only decides whether a link is sent; confirm_change_email
        is the line that assigns user.email. It exists for the address that
        becomes taken between the request and the click -- which the submit
        branch cannot see -- so it needs its own proof, and the case variant is
        precisely the shape it used to miss.
        """
        user = self.login(AdminFactory())
        original_email = user.email
        UserFactory(email="Maria@example.com")

        security = current_app.extensions["security"]
        data = [str(user.fs_uniquifier), hash_data(user.email), "maria@example.com"]
        token = security.confirm_serializer.dumps(data)

        resp = self.get(url_for("security.confirm_change_email", token=token))

        assert resp.status_code == 302
        assert "change_email_already_taken" in resp.location
        user.reload()
        assert user.email == original_email

    def test_change_mail_recasing_own_address_is_still_allowed(self):
        """Widening "taken" must not lock the owner out of their own address.

        The identity guard is what saves this, and it only works because the
        lookup prefers the exactly matching row: asked for their own spelling,
        it returns their own row, so existing.id == current_user.id.
        """
        user = self.login(UserFactory(email="maria@example.com", password=None))

        with capture_mails() as mails:
            resp = self._submit_change_email("Maria@example.com")

        assert resp.status_code == 302
        # A confirmation link to the new spelling -- not a refusal, and not the
        # address-taken warning, which would have gone to the same mailbox and
        # is why the recipient alone does not settle it.
        assert len(mails) == 1
        assert mails[0].recipients == ["Maria@example.com"]

        # And the click goes through: confirm_change_email applies the same
        # widened lookup, so the identity guard has to hold there too.
        security = current_app.extensions["security"]
        data = [str(user.fs_uniquifier), hash_data(user.email), "Maria@example.com"]
        token = security.confirm_serializer.dumps(data)
        confirmed = self.get(url_for("security.confirm_change_email", token=token))

        assert "change_email_already_taken" not in confirmed.location
        user.reload()
        assert user.email == "Maria@example.com"
