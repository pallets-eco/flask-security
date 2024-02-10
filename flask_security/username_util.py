"""
    flask_security.username_util
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Utility class providing methods for validating and normalizing usernames.

    :copyright: (c) 2020-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

"""

from __future__ import annotations

import typing as t
import unicodedata

from .utils import (
    config_value as cv,
    get_message,
)

if t.TYPE_CHECKING:  # pragma: no cover
    import flask


class UsernameUtil:
    """
    Utility class providing methods for validating and normalizing usernames.

    To provide your own implementation, pass in the class as ``username_util_cls``
    at init time.  Your class will be instantiated once as part of app initialization.

    .. versionadded:: 4.1.0
    """

    def __init__(self, app: flask.Flask):
        """Instantiate class.

        :param app: The Flask application being initialized.
        """
        pass

    def check_username(self, username: str) -> str | None:
        """
        Given a username - check for allowable character categories.
        This is broken out so applications can easily override this method only.

        By default allow letters and numbers (using unicodedata.category).

        Returns None if allowed, error message if not allowed.
        """
        cats = [unicodedata.category(c)[0] for c in username]
        if any([cat not in ["L", "N"] for cat in cats]):
            return get_message("USERNAME_DISALLOWED_CHARACTERS")[0]
        return None

    def normalize(self, username: str) -> str:
        """
        Given an input username - return a clean (using bleach) and normalized
        (using Python's unicodedata.normalize()) version.
        Must be called in app context and uses
        :py:data:`SECURITY_USERNAME_NORMALIZE_FORM` config variable.
        """
        import bleach

        if not username:
            return ""

        username = bleach.clean(username.strip(), strip=True)
        if not username:
            return ""
        cf = cv("USERNAME_NORMALIZE_FORM")
        if cf:
            return unicodedata.normalize(cf, username)
        return username

    def validate(self, username: str) -> tuple[str | None, str | None]:
        """
        Username validation.
        Called in app/request context.

        The username is first validated then normalized.
        Input is restricted/validated via a call to check_username.
        Return value is a tuple (msg, normalized_username). msg will be None if
        properly validated.

        It is important that None be returned if data is an empty string since
        otherwise DBs will complain since the field is unique/nullable.
        """
        import bleach

        if not username:
            return None, None
        uclean = bleach.clean(username.strip(), strip=True)
        if uclean != username:
            return get_message("USERNAME_ILLEGAL_CHARACTERS")[0], None

        msg = self.check_username(uclean)
        if msg:
            return msg, None

        unorm = self.normalize(username)
        umin = cv("USERNAME_MIN_LENGTH")
        umax = cv("USERNAME_MAX_LENGTH")
        if len(unorm) < umin or len(unorm) > umax:
            return get_message("USERNAME_INVALID_LENGTH", min=umin, max=umax)[0], unorm
        return None, unorm
