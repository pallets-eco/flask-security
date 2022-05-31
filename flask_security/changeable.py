"""
    flask_security.changeable
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security change password module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2022 by J. Christopher Wagner (jwag).
    :author: Eskil Heyn Olsen
    :license: MIT, see LICENSE for more details.
"""
import typing as t

from flask import current_app, request, session
from flask_login import COOKIE_NAME as REMEMBER_COOKIE_NAME

from .proxies import _datastore
from .signals import password_changed
from .utils import config_value as cv, hash_password, login_user, send_mail

if t.TYPE_CHECKING:  # pragma: no cover
    from .datastore import User


def send_password_changed_notice(user):
    """Sends the password changed notice email for the specified user.

    :param user: The user to send the notice to
    """
    if cv("SEND_PASSWORD_CHANGE_EMAIL"):
        subject = cv("EMAIL_SUBJECT_PASSWORD_CHANGE_NOTICE")
        send_mail(subject, user.email, "change_notice", user=user)


def change_user_password(
    user: "User", password: t.Optional[str], notify: bool = True, autologin: bool = True
) -> None:
    """Change the specified user's password

    :param user: The user object
    :param password: The unhashed new password
    :param notify: if True send notification (if configured) to user
    :param autologin: if True, login user
    """

    if password:
        user.password = hash_password(password)
    else:
        user.password = None
    # Change uniquifier - this will cause ALL sessions to be invalidated.
    _datastore.set_uniquifier(user)
    _datastore.put(user)

    if autologin:
        # re-login user - this will update session, optional remember etc.
        remember_cookie_name = current_app.config.get(
            "REMEMBER_COOKIE_NAME", REMEMBER_COOKIE_NAME
        )
        has_remember_cookie = (
            remember_cookie_name in request.cookies
            and session.get("remember") != "clear"
        )
        login_user(user, remember=has_remember_cookie, authn_via=["change"])
    if notify:
        send_password_changed_notice(user)
    password_changed.send(current_app._get_current_object(), user=user)  # type: ignore


def admin_change_password(user: "User", new_passwd: str, notify: bool = True) -> None:
    """
    Administratively change a user's password.
    Note that this will immediately render the user's existing sessions (and possibly
    authentication tokens) invalid.

    It is up to the caller to inform the user of their new password by some
    out-of-band means.

    :param user: The user object to change
    :param new_passwd: The new plain-text password to assign to the user.
    :param notify: If True and SECURITY_SEND_PASSWORD_CHANGE_EMAIL is True
        send the 'change_notice' email to the user.
    """
    change_user_password(user, new_passwd, notify=notify, autologin=False)
