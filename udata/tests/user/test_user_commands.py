from datetime import datetime

from udata.core.user.constants import (
    SAML_PLACEHOLDER_EMAIL_DOMAIN,
    SAML_PLACEHOLDER_EMAIL_PREFIX,
)
from udata.core.user.factories import UserFactory
from udata.core.user.models import User
from udata.core.user.nic import hash_nic
from udata.tests.api import PytestOnlyDBTestCase

PLAIN_NIC = "08133404"
OTHER_NIC = "12345678"
LEGACY_ENCRYPTED_NIC = "ab12" * 128  # 512 hex chars, legacy portal ciphertext
JUNK_NIC = "johndoe"


def placeholder_email(slug):
    return f"{SAML_PLACEHOLDER_EMAIL_PREFIX}{slug}@{SAML_PLACEHOLDER_EMAIL_DOMAIN}"


class MigrateNicsHashPhaseTest(PytestOnlyDBTestCase):
    def test_hashes_plain_nics(self):
        user = UserFactory(extras={"auth_nic": PLAIN_NIC})

        self.cli("user", "migrate-nics")

        user.reload()
        with self.app.app_context():
            assert user.extras["auth_nic"] == hash_nic(PLAIN_NIC)

    def test_leaves_hashed_nics_untouched(self):
        with self.app.app_context():
            hashed = hash_nic(PLAIN_NIC)
        user = UserFactory(extras={"auth_nic": hashed})

        self.cli("user", "migrate-nics")

        user.reload()
        assert user.extras["auth_nic"] == hashed

    def test_leaves_legacy_encrypted_nics_untouched(self):
        user = UserFactory(extras={"auth_nic": LEGACY_ENCRYPTED_NIC})

        self.cli("user", "migrate-nics")

        user.reload()
        assert user.extras["auth_nic"] == LEGACY_ENCRYPTED_NIC

    def test_leaves_unrecognized_values_untouched(self):
        user = UserFactory(extras={"auth_nic": JUNK_NIC})

        self.cli("user", "migrate-nics")

        user.reload()
        assert user.extras["auth_nic"] == JUNK_NIC

    def test_dry_run_changes_nothing(self):
        user = UserFactory(extras={"auth_nic": PLAIN_NIC})

        self.cli("user", "migrate-nics", "--dry-run")

        user.reload()
        assert user.extras["auth_nic"] == PLAIN_NIC


class MigrateNicsMergePhaseTest(PytestOnlyDBTestCase):
    def test_merges_duplicate_with_hashed_nic_without_double_hashing(self):
        with self.app.app_context():
            hashed = hash_nic(PLAIN_NIC)
        target = UserFactory(first_name="Cristina", last_name="Isidro")
        dup = UserFactory(
            email=placeholder_email("aaaa1111"),
            first_name="Cristina",
            last_name="Isidro",
            extras={"auth_nic": hashed},
        )

        self.cli("user", "migrate-nics")

        target.reload()
        assert target.extras["auth_nic"] == hashed
        assert User.objects(id=dup.id).first() is None

    def test_merges_duplicate_with_plain_nic_hashing_it_once(self):
        target = UserFactory(first_name="Cristina", last_name="Isidro")
        dup = UserFactory(
            email=placeholder_email("bbbb2222"),
            first_name="Cristina",
            last_name="Isidro",
            extras={"auth_nic": PLAIN_NIC},
        )

        self.cli("user", "migrate-nics")

        target.reload()
        with self.app.app_context():
            assert target.extras["auth_nic"] == hash_nic(PLAIN_NIC)
        assert User.objects(id=dup.id).first() is None

    def test_skips_when_target_linked_to_another_identity(self):
        with self.app.app_context():
            target_nic = hash_nic(OTHER_NIC)
        target = UserFactory(
            first_name="Cristina", last_name="Isidro", extras={"auth_nic": target_nic}
        )
        dup = UserFactory(
            email=placeholder_email("cccc3333"),
            first_name="Cristina",
            last_name="Isidro",
            extras={"auth_nic": PLAIN_NIC},
        )

        self.cli("user", "migrate-nics")

        target.reload()
        assert target.extras["auth_nic"] == target_nic
        assert User.objects(id=dup.id).first() is not None

    def test_skips_when_duplicate_nic_has_unexpected_format(self):
        UserFactory(first_name="Cristina", last_name="Isidro")
        dup = UserFactory(
            email=placeholder_email("dddd4444"),
            first_name="Cristina",
            last_name="Isidro",
            extras={"auth_nic": LEGACY_ENCRYPTED_NIC},
        )

        self.cli("user", "migrate-nics")

        dup.reload()
        assert dup.extras["auth_nic"] == LEGACY_ENCRYPTED_NIC

    def test_ignores_deleted_candidates(self):
        UserFactory(first_name="Cristina", last_name="Isidro", deleted=datetime.utcnow())
        dup = UserFactory(
            email=placeholder_email("eeee5555"),
            first_name="Cristina",
            last_name="Isidro",
            extras={"auth_nic": PLAIN_NIC},
        )

        self.cli("user", "migrate-nics")

        # No living candidate: the duplicate must survive, untouched by phase 2
        # (phase 1 still hashes its plain NIC).
        dup.reload()
        with self.app.app_context():
            assert dup.extras["auth_nic"] == hash_nic(PLAIN_NIC)

    def test_skips_on_multiple_name_matches(self):
        homonyms = [UserFactory(first_name="Cristina", last_name="Isidro") for _ in range(2)]
        dup = UserFactory(
            email=placeholder_email("ffff6666"),
            first_name="Cristina",
            last_name="Isidro",
            extras={"auth_nic": PLAIN_NIC},
        )

        self.cli("user", "migrate-nics")

        assert User.objects(id=dup.id).first() is not None
        for homonym in homonyms:
            homonym.reload()
            assert "auth_nic" not in (homonym.extras or {})


class MigrateNicsEndToEndTest(PytestOnlyDBTestCase):
    def test_mixed_formats_end_state(self):
        with self.app.app_context():
            already_hashed = hash_nic("99999999")
        plain_user = UserFactory(extras={"auth_nic": PLAIN_NIC})
        hashed_user = UserFactory(extras={"auth_nic": already_hashed})
        legacy_user = UserFactory(extras={"auth_nic": LEGACY_ENCRYPTED_NIC})
        junk_user = UserFactory(extras={"auth_nic": JUNK_NIC})
        target = UserFactory(first_name="Rui", last_name="Martinho")
        dup = UserFactory(
            email=placeholder_email("abcd0123"),
            first_name="Rui",
            last_name="Martinho",
            extras={"auth_nic": OTHER_NIC},
        )

        result = self.cli("user", "migrate-nics")

        for user in (plain_user, hashed_user, legacy_user, junk_user, target):
            user.reload()
        with self.app.app_context():
            assert plain_user.extras["auth_nic"] == hash_nic(PLAIN_NIC)
            assert target.extras["auth_nic"] == hash_nic(OTHER_NIC)
        assert hashed_user.extras["auth_nic"] == already_hashed
        assert legacy_user.extras["auth_nic"] == LEGACY_ENCRYPTED_NIC
        assert junk_user.extras["auth_nic"] == JUNK_NIC
        assert User.objects(id=dup.id).first() is None
        assert "2 NIC(s) hashed" in result.output
        assert "1 duplicate(s) merged" in result.output

    def test_is_idempotent(self):
        user = UserFactory(extras={"auth_nic": PLAIN_NIC})

        self.cli("user", "migrate-nics")
        self.cli("user", "migrate-nics")

        user.reload()
        with self.app.app_context():
            assert user.extras["auth_nic"] == hash_nic(PLAIN_NIC)
