"""
    flask_security.registerable
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security registerable module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2022 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""
import typing as t

from flask import current_app as app

from .confirmable import generate_confirmation_link
from .forms import form_errors_munge
from .proxies import _security, _datastore
from .signals import user_registered, user_not_registered
from .utils import (
    config_value as cv,
    do_flash,
    get_message,
    hash_password,
    send_mail,
    url_for_security,
)

if t.TYPE_CHECKING:
    from .forms import ConfirmRegisterForm


def register_user(registration_form):
    """
    Calls datastore to create user, triggers post-registration logic
    (e.g. sending confirmation link, sending registration mail)
    :param registration_form: form with user registration data
    :return: user instance
    """

    user_model_kwargs = registration_form.to_dict(only_user=True)

    # passwords are not always required -
    # with UNIFIED_SIGNIN and PASSWORD_REQUIRED=False
    if user_model_kwargs["password"]:
        user_model_kwargs["password"] = hash_password(user_model_kwargs["password"])
    user = _datastore.create_user(**user_model_kwargs)

    # if they didn't give a password - auto-setup email magic links (if UNIFIED SIGNIN)
    if not user_model_kwargs["password"] and cv("UNIFIED_SIGNIN"):
        _datastore.us_setup_email(user)

    confirmation_link, token = None, None
    if _security.confirmable:
        confirmation_link, token = generate_confirmation_link(user)
        do_flash(*get_message("CONFIRM_REGISTRATION", email=user.email))

    user_registered.send(
        app._get_current_object(),
        user=user,
        confirm_token=token,
        confirmation_token=token,
        form_data=registration_form.to_dict(only_user=False),
    )

    if cv("SEND_REGISTER_EMAIL"):
        send_mail(
            cv("EMAIL_SUBJECT_REGISTER"),
            user.email,
            "welcome",
            user=user,
            confirmation_link=confirmation_link,
            confirmation_token=token,
        )

    return user


def register_existing(form: "ConfirmRegisterForm") -> bool:
    """
    In the case of generic responses we want to mitigate any possible
    email/username enumeration.
    For an existing email we send an email to that address and tell them they
    are already registered (and provide their username if any).

    N.B. This (and forgot and confirm) could be used to DDOS an email by constantly
    issuing requests. One way to mitigate that is to use signals and add specific
    application code.

    """

    if not (
        cv("RETURN_GENERIC_RESPONSES")
        or form.existing_username_user
        or form.existing_email_user
    ):  # pragma: no cover
        return False

    # There are 2 classes of error - an existing email/username and non-compliant
    # username/password. We want to give the user feedback on a non-compliant
    # username/password - but not give away whether the email/username is already taken.
    # Since in this case we have an 'existing' entry - we simply Null out those
    # errors.
    # This also means for JSON there is no way to tell if things worked or not.
    fields_to_squash: t.Dict[str, t.Dict[str, str]] = dict(email=dict())
    if hasattr(form, "username") and form.existing_username_user:
        fields_to_squash["username"] = dict()
    form_errors_munge(form, fields_to_squash)
    if form.errors:
        # some other illegal password/username - return an error
        return False

    # only errors were existing email/username
    hash_password("not-a-password")  # reduce timing between successful and not.

    # Same as is done in register_user()
    if _security.confirmable:
        do_flash(*get_message("CONFIRM_REGISTRATION", email=form.email.data))

    # 2 cases:
    # 1) existing email (an already registered account) empty or same username
    # 2) new email with existing username (which corresponds to some OTHER account)

    if form.existing_email_user:
        user_not_registered.send(
            app._get_current_object(),  # type: ignore
            user=form.existing_email_user,
            existing_email=True,
            existing_username=form.existing_username_user is not None,
            form_data=form.to_dict(only_user=False),
        )
        # Send a nice email saying they are already registered - tell them their
        # existing username if they have one, and suggest how to reset password.
        recovery_link = None
        if _security.recoverable:
            recovery_link = url_for_security("forgot_password", _external=True)
        if cv("SEND_REGISTER_EMAIL"):
            send_mail(
                cv("EMAIL_SUBJECT_REGISTER"),
                form.existing_email_user.email,
                "welcome_existing",
                user=form.existing_email_user,
                recovery_link=recovery_link,
            )
    elif form.existing_username_user:
        # New email, already taken username.
        # Note that we send email to NEW email - so it is possible for a bad-actor
        # to enumerate usernames (slowly).
        user_not_registered.send(
            app._get_current_object(),  # type:ignore
            user=None,
            existing_email=False,
            existing_username=True,
            form_data=form.to_dict(only_user=False),
        )
        if cv("SEND_REGISTER_EMAIL"):
            send_mail(
                cv("EMAIL_SUBJECT_REGISTER"),
                form.email.data,
                "welcome_existing_username",
                email=form.email.data,
                username=form.username.data if hasattr(form, "username") else None,
            )

    return True
