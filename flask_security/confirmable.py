"""
flask_security.confirmable
~~~~~~~~~~~~~~~~~~~~~~~~~~

Flask-Security confirmable module

:copyright: (c) 2012 by Matt Wright.
:copyright: (c) 2017 by CERN.
:copyright: (c) 2021-2026 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.
"""

from flask import current_app

from .proxies import _security, _datastore
from .signals import confirm_instructions_sent, user_confirmed
from .utils import (
    config_value as cv,
    hash_data,
    send_mail,
    url_for_security,
    check_and_get_token_status,
    verify_hash,
)


def generate_confirmation_link(user):
    token = generate_confirmation_token(user)
    return url_for_security("confirm_email", token=token, _external=True), token


def send_confirmation_instructions(user):
    """Sends the confirmation instructions email for the specified user.

    :param user: The user to send the instructions to
    """

    confirmation_link, token = generate_confirmation_link(user)

    send_mail(
        cv("EMAIL_SUBJECT_CONFIRM"),
        user.email,
        "confirmation_instructions",
        user=user,
        confirmation_link=confirmation_link,
        confirmation_token=token,
    )

    confirm_instructions_sent.send(
        current_app._get_current_object(),
        _async_wrapper=current_app.ensure_sync,
        user=user,
        token=token,
        confirmation_token=token,
    )


def generate_confirmation_token(user):
    """Generates a unique confirmation token for the specified user.

    :param user: The user to work with
    """
    data = [str(user.fs_uniquifier), hash_data(user.email)]
    return _security.confirm_serializer.dumps(data)


def requires_confirmation(user):
    """Returns `True` if the user requires confirmation."""
    return (
        _security.confirmable
        and not cv("LOGIN_WITHOUT_CONFIRMATION")
        and user.confirmed_at is None
    )


def confirm_email_token_status(token):
    """Returns the expired status, invalid status, and user of a confirmation
    token. For example::

        expired, invalid, user = confirm_email_token_status('...')

    Always check invalid and expiration first - 'user' could be returned in any case
    :param token: The confirmation token
    """
    expired, invalid, data = check_and_get_token_status(
        token, "confirm", cv("CONFIRM_EMAIL_WITHIN")
    )
    if invalid or expired or not data:
        return expired, invalid, None
    if not (user := _datastore.find_user(fs_uniquifier=data[0])):
        return expired, True, None
    invalid = not verify_hash(data[1], user.email)
    return expired, invalid, user


def confirm_user(user):
    """Confirms the specified user

    :param user: The user to confirm
    """
    if user.confirmed_at is not None:
        return False
    user.confirmed_at = _security.datetime_factory()
    _datastore.put(user)
    user_confirmed.send(
        current_app._get_current_object(),
        _async_wrapper=current_app.ensure_sync,
        user=user,
    )
    return True
