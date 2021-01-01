"""
    flask_security.changeable
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security recoverable module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :author: Eskil Heyn Olsen
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app, request, session
from flask_login import COOKIE_NAME as REMEMBER_COOKIE_NAME
from werkzeug.local import LocalProxy

from .signals import password_changed
from .utils import config_value, hash_password, login_user, send_mail

# Convenient references
_security = LocalProxy(lambda: current_app.extensions["security"])

_datastore = LocalProxy(lambda: _security.datastore)


def send_password_changed_notice(user):
    """Sends the password changed notice email for the specified user.

    :param user: The user to send the notice to
    """
    if config_value("SEND_PASSWORD_CHANGE_EMAIL"):
        subject = config_value("EMAIL_SUBJECT_PASSWORD_CHANGE_NOTICE")
        send_mail(subject, user.email, "change_notice", user=user)


def change_user_password(user, password):
    """Change the specified user's password

    :param user: The user to change_password
    :param password: The unhashed new password
    """
    user.password = hash_password(password)
    # Change uniquifier - this will cause ALL sessions to be invalidated.
    _datastore.set_uniquifier(user)
    _datastore.put(user)

    # re-login user - this will update session, optional remember etc.
    remember_cookie_name = current_app.config.get(
        "REMEMBER_COOKIE_NAME", REMEMBER_COOKIE_NAME
    )
    has_remember_cookie = (
        remember_cookie_name in request.cookies and session.get("remember") != "clear"
    )
    login_user(user, remember=has_remember_cookie, authn_via=["change"])
    send_password_changed_notice(user)
    password_changed.send(current_app._get_current_object(), user=user)
