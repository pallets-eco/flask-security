# -*- coding: utf-8 -*-
"""
    flask_security.confirmable
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security confirmable module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2017 by CERN.
    :license: MIT, see LICENSE for more details.
"""

import urllib.parse

from flask import current_app as app
from werkzeug.local import LocalProxy

from .signals import confirm_instructions_sent, user_confirmed
from .utils import config_value, get_token_status, hash_data, send_mail, \
    url_for_security, verify_hash

# Convenient references
_security = LocalProxy(lambda: app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def generate_confirmation_link(user):
    token = generate_confirmation_token(user)
    return (
        url_for_security('confirm_email', token=token, _external=True),
        token
    )


def send_confirmation_instructions(user):
    """Sends the confirmation instructions email for the specified user.

    :param user: The user to send the instructions to
    """

    confirmation_link, token = generate_confirmation_link(user)
    if _security.link_host:
        # useful for testing when UI is separate from backend
        link_parse = urllib.parse.urlsplit(confirmation_link)
        confirmation_link = urllib.parse.urlunsplit(link_parse._replace(netloc = _security.link_host))

    send_mail(config_value('EMAIL_SUBJECT_CONFIRM'), user.email,
              'confirmation_instructions', user=user,
              confirmation_link=confirmation_link)

    confirm_instructions_sent.send(app._get_current_object(), user=user,
                                   token=token)


def generate_confirmation_token(user):
    """Generates a unique confirmation token for the specified user.

    :param user: The user to work with
    """
    data = [str(user.id), hash_data(user.email)]
    return _security.confirm_serializer.dumps(data)


def requires_confirmation(user):
    """Returns `True` if the user requires confirmation."""
    return (_security.confirmable and
            not _security.login_without_confirmation and
            user.confirmed_at is None)


def confirm_email_token_status(token):
    """Returns the expired status, invalid status, and user of a confirmation
    token. For example::

        expired, invalid, user = confirm_email_token_status('...')

    :param token: The confirmation token
    """
    expired, invalid, user, token_data = \
        get_token_status(token, 'confirm', 'CONFIRM_EMAIL', return_data=True)
    if not invalid and user:
        user_id, token_email_hash = token_data
        invalid = not verify_hash(token_email_hash, user.email)
    return expired, invalid, user


def confirm_user(user):
    """Confirms the specified user

    :param user: The user to confirm
    """
    if user.confirmed_at is not None:
        return False
    user.confirmed_at = _security.datetime_factory()
    _datastore.put(user)
    user_confirmed.send(app._get_current_object(), user=user)
    return True
