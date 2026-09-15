"""
We have our own system to build mails without Jinja templates with `MailMessage`.
To connect our system with the system from flask_security we need to override the Jinja
`render_template` function, create our MailMessage, and generate the HTML or text version.
`flask_security` then call the standard mail method from flask to send these strings.

In `render_mail_template` we support a few mails but not all. We could fallback to the regular
Jinja render function, but since we don't have any mails' templates defined in our application
the render function will crash, so we crash early in the `render_mail_template` function.

Note that `flask_security` have default templates for all mails but we create our own blueprint
specifying our `template` folder for templates and the system is not intelligent enough to try
our folder before fallbacking to the templates inside the `flask_security` package.
"""

import logging

from flask import current_app

from udata.mail import MailCTA, MailMessage

log = logging.getLogger(__name__)


def render_mail_template(template_name_or_list: str | list[str], **kwargs):
    if not isinstance(template_name_or_list, str):
        return None

    if not template_name_or_list.startswith("security/email/"):
        return None

    if not template_name_or_list.endswith(".txt") and not template_name_or_list.endswith(".html"):
        return None

    (name, format) = template_name_or_list.removeprefix("security/email/").split(".")

    mail_message = None

    match name:
        case "welcome":
            mail_message = welcome(**kwargs)
        case "welcome_existing":
            mail_message = welcome_existing(**kwargs)
        case "confirmation_instructions":
            mail_message = confirmation_instructions(**kwargs)
        case "reset_instructions":
            mail_message = reset_instructions(**kwargs)
        case "reset_notice":
            mail_message = reset_notice(**kwargs)
        case "change_notice":
            mail_message = change_notice(**kwargs)
        case "two_factor_rescue":
            mail_message = two_factor_rescue(**kwargs)
        case _:
            raise Exception(f"Unknown mail message template: {name}")

    if format == "txt":
        return mail_message.text(kwargs.get("user"))
    elif format == "html":
        return mail_message.html(kwargs.get("user"))
    else:
        raise Exception(f"Mail message with unknown format: {name} (txt or html supported)")


def welcome(confirmation_link: str, **kwargs) -> MailMessage:
    from udata.i18n import lazy_gettext as _

    return MailMessage(
        subject=_("Confirm your email address"),
        paragraphs=[
            _("Welcome to %(site)s!", site=current_app.config["SITE_TITLE"]),
            _("Please confirm your email address."),
            MailCTA(_("Confirm your email address"), confirmation_link),
        ],
    )


def welcome_existing(recovery_link: str, **kwargs) -> MailMessage:
    from udata.i18n import lazy_gettext as _

    return MailMessage(
        subject=_("Account information"),
        paragraphs=[
            _(
                "You received this email because a registration was attempted on %(site)s with your email address.",
                site=current_app.config["SITE_TITLE"],
            ),
            _("If you forgot your password, you can reset it."),
            MailCTA(_("Reset your password"), recovery_link),
        ],
    )


def registration_association_refused_notice(**kwargs) -> MailMessage:
    """Tell the owner their account could not be associated, and what to do.

    The sibling notice cannot serve this case. Its one actionable line is
    "sign in to that account the way you normally do", which is impossible
    advice for the person who triggers this: they are held on the registration
    completion screen and cannot sign in anywhere until it lets them through.
    Its docstring declines to prescribe a step because it cannot know the
    case; here the case is known, so this one says it.

    Carries no link, for the same reason as its sibling and one more: there is
    nothing a link could do. The association was refused because the temporary
    account already holds work of its own, and nothing this mail can offer
    resolves that without somebody deciding what happens to it.

    Says nothing about the temporary account beyond its existence -- no names,
    no counts, no titles. The recipient is the owner of this address, which is
    not by itself proof that they are the same person as the one who submitted
    it.
    """
    from udata.i18n import lazy_gettext as _

    site = current_app.config["SITE_TITLE"]
    return MailMessage(
        kind="registration_association_refused",
        subject=_("Your %(site)s account could not be linked", site=site),
        paragraphs=[
            _(
                "You received this email because someone signing in to %(site)s with a "
                "digital identity asked to link it to the account that uses this address.",
                site=site,
            ),
            _(
                "It was not linked. The temporary account created for that sign-in "
                "already holds content of its own, and linking would have discarded it. "
                "Nothing was changed on either account."
            ),
            _(
                "If it was you, contact support so the two accounts can be sorted out "
                "together. If it was not you, no action is needed: your account is "
                "untouched and nobody gained access to it."
            ),
        ],
    )


def address_taken_notice(**kwargs) -> MailMessage:
    """Tell the owner of an address that a change-email request named it.

    The counterpart of the identical answer `change_email` gives either way:
    the browser learns nothing about the address, and the only party told
    anything is whoever can read that mailbox.

    Deliberately carries no link of any kind. A confirmation link here would
    act on an account the requesting session has proved nothing about, and
    would be a way to spray confirmation mail at any address on demand. It also
    prescribes no particular next step: the account may have been created
    through SAML and have no usable password, so "use your password" would be
    impossible advice.

    This is now the FALLBACK of that branch rather than all of it. A caller
    still completing a government-identity registration is mailed an
    association link instead -- a different instrument, granting the requesting
    session nothing and acting only when the mailbox's owner clicks it (see
    _mail_registration_association_link, LEDG-2431). This notice is what the
    branch sends whenever that path does not apply or its guards refuse, and
    the caller cannot tell the two apart: the response is the shared one.

    The sibling notice in the SAML migration wizard says the same thing for
    that flow, and is kept separate on purpose -- its copy names a digital
    identity, which is false here, because `change_email` is also reached from
    the profile by a password user.
    """
    from udata.i18n import lazy_gettext as _

    site = current_app.config["SITE_TITLE"]
    return MailMessage(
        kind="change_email_address_taken",
        subject=_("Your %(site)s account already exists", site=site),
        paragraphs=[
            _(
                "You received this email because someone tried to use your email "
                "address on %(site)s. It already belongs to an account, so nothing "
                "was created and nothing changed.",
                site=site,
            ),
            _(
                "If it was you, sign in to that account the way you normally "
                "do, or use the account recovery if you cannot."
            ),
            _("If it was not you, no action is needed. Your account is untouched."),
        ],
    )


def confirmation_instructions(confirmation_link: str, **kwargs) -> MailMessage:
    from udata.i18n import lazy_gettext as _

    return MailMessage(
        subject=_("Confirm your email address"),
        paragraphs=[
            _("Please confirm your email address."),
            MailCTA(_("Confirm your email address"), confirmation_link),
        ],
    )


def reset_instructions(reset_token: str, **kwargs) -> MailMessage:
    from udata.uris import cdata_url

    return MailMessage(
        subject="Redefinição de palavra-passe — dados.gov.pt",
        paragraphs=[
            "Alguém pediu uma redefinição da palavra-passe da sua conta no dados.gov.pt.",
            "Caso não tenha efetuado este pedido, ignore este e-mail.",
            MailCTA(
                "Redefinir a sua palavra-passe",
                cdata_url(f"/reset-password/{reset_token}"),
            ),
        ],
    )


def reset_notice(**kwargs) -> MailMessage:
    from udata.uris import cdata_url

    return MailMessage(
        subject="A sua palavra-passe foi redefinida — dados.gov.pt",
        paragraphs=[
            "A sua palavra-passe dados.gov.pt foi redefinida.",
            MailCTA("Visitar dados.gov.pt", cdata_url("/")),
        ],
    )


def change_notice(**kwargs) -> MailMessage:
    from udata.i18n import lazy_gettext as _
    from udata.uris import cdata_url

    return MailMessage(
        subject=_("Your password has been changed"),
        paragraphs=[
            _(
                "Your %(site)s account password has been changed.",
                site=current_app.config["SITE_TITLE"],
            ),
            _("If you did not change your password, please reset it."),
            MailCTA(_("Reset your password"), cdata_url("/reset/")),
        ],
    )


def two_factor_rescue(user, **kwargs) -> MailMessage:
    from udata.i18n import lazy_gettext as _

    return MailMessage(
        subject=_("User can't access mail account"),
        paragraphs=[
            _("%(email)s can not access mail account", email=user.email),
        ],
    )
