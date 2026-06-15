"""
flask_security.recoverable
~~~~~~~~~~~~~~~~~~~~~~~~~~

Flask-Security recoverable module

:copyright: (c) 2012 by Matt Wright.
:copyright: (c) 2019-2026 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.
"""

from flask import current_app
from .proxies import _security, _datastore
from .signals import (
    password_reset,
    reset_password_instructions_sent,
    username_recovery_email_sent,
)
from .utils import (
    config_value,
    hash_data,
    hash_password,
    send_mail,
    url_for_security,
    check_and_get_token_status,
    get_within_delta,
)


def generate_reset_link(user):
    token = generate_reset_password_token(user)
    return url_for_security("reset_password", token=token, _external=True), token


def send_reset_password_instructions(user):
    """Sends the reset password instructions email for the specified user.

    :param user: The user to send the instructions to
    """
    reset_link, token = generate_reset_link(user)

    if config_value("SEND_PASSWORD_RESET_EMAIL"):
        send_mail(
            config_value("EMAIL_SUBJECT_PASSWORD_RESET"),
            user.email,
            "reset_instructions",
            user=user,
            reset_link=reset_link,
            reset_token=token,
        )

    reset_password_instructions_sent.send(
        current_app._get_current_object(),
        _async_wrapper=current_app.ensure_sync,
        user=user,
        token=token,
        reset_token=token,
    )


def send_password_reset_notice(user):
    """Sends the password reset notice email for the specified user.

    :param user: The user to send the notice to
    """
    if config_value("SEND_PASSWORD_RESET_NOTICE_EMAIL"):
        send_mail(
            config_value("EMAIL_SUBJECT_PASSWORD_NOTICE"),
            user.email,
            "reset_notice",
            user=user,
        )


def generate_reset_password_token(user):
    """Generates a unique reset password token for the specified user.

    :param user: The user to work with
    """
    password_hash = hash_data(user.password) if user.password else None
    data = [str(user.fs_uniquifier), password_hash]
    return _security.reset_serializer.dumps(data)


def reset_password_token_status(token):
    """Returns the expired status, invalid status, and user of a password reset
    token. For example::

        expired, invalid, user, data = reset_password_token_status('...')

    :param token: The password reset token
    """
    user = None
    expired, invalid, data = check_and_get_token_status(
        token, "reset", get_within_delta("RESET_PASSWORD_WITHIN")
    )
    if data:
        user = _datastore.find_user(fs_uniquifier=data[0])

    return expired, invalid, user


def update_password(user, password):
    """Update the specified user's password

    :param user: The user to update_password
    :param password: The unhashed new password
    """
    user.password = hash_password(password)
    # Change uniquifier - this will cause ALL sessions to be invalidated.
    _datastore.set_uniquifier(user)
    _datastore.put(user)
    send_password_reset_notice(user)
    password_reset.send(
        current_app._get_current_object(),
        _async_wrapper=current_app.ensure_sync,
        user=user,
    )


def send_username_recovery_email(user):
    """Sends the username recovery email for the specified user.
    :param user: The user requesting username recovery
    """
    if config_value("USERNAME_RECOVERY"):
        send_mail(
            config_value("EMAIL_SUBJECT_USERNAME_RECOVERY"),
            user.email,
            "username_recovery",
            user=user,
            username=user.username,
        )
        username_recovery_email_sent.send(
            current_app._get_current_object(),
            _async_wrapper=current_app.ensure_sync,
            user=user,
        )
