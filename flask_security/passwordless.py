"""
    flask_security.passwordless
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security passwordless module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2021 by Chris Wagner.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app as app

from .proxies import _security
from .signals import login_instructions_sent
from .utils import config_value, get_token_status, send_mail, url_for_security


def send_login_instructions(user):
    """Sends the login instructions email for the specified user.

    :param user: The user to send the instructions to
    """
    token = generate_login_token(user)
    login_link = url_for_security("token_login", token=token, _external=True)

    send_mail(
        config_value("EMAIL_SUBJECT_PASSWORDLESS"),
        user.email,
        "login_instructions",
        user=user,
        login_link=login_link,
        login_token=token,
    )

    login_instructions_sent.send(
        app._get_current_object(), user=user, login_token=token
    )


def generate_login_token(user):
    """Generates a unique login token for the specified user.

    :param user: The user the token belongs to
    """
    return _security.login_serializer.dumps([str(user.fs_uniquifier)])


def login_token_status(token):
    """Returns the expired status, invalid status, and user of a login token.
    For example::

        expired, invalid, user = login_token_status('...')

    :param token: The login token
    """
    return get_token_status(token, "login", "LOGIN")
