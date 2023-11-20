"""
    flask_security.recoverable
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security recoverable module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2023 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app
from .proxies import _security, _datastore
from .signals import password_reset, reset_password_instructions_sent
from .utils import (
    config_value,
    get_token_status,
    hash_data,
    hash_password,
    send_mail,
    url_for_security,
    verify_hash,
)


def send_reset_password_instructions(user):
    """Sends the reset password instructions email for the specified user.

    :param user: The user to send the instructions to
    """
    token = generate_reset_password_token(user)
    reset_link = url_for_security("reset_password", token=token, _external=True)

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
    expired, invalid, user, data = get_token_status(
        token, "reset", "RESET_PASSWORD", return_data=True
    )
    # This check looks to see if the password has been changed since the reset token
    # was created. As of #338 - we reset the fs_uniquifier on each password change
    # so the token would have been marked invalid above.
    # This made sure that the token couldn't be used twice.
    # TODO - look at removing this entire check.
    if not invalid and user:
        if user.password:
            if not verify_hash(data[1], user.password):
                invalid = True

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
