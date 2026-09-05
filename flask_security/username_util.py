"""
flask_security.username_util
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Utility class providing methods for validating and normalizing usernames.

:copyright: (c) 2020-2026 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.

"""

from __future__ import annotations

import typing as t

from .utils import (
    _config_value as cv,
    get_message,
    input_svn,
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

    def normalize(self, username: str) -> str | None:
        """
        Given an input username - return a clean (using nh3) and normalized
        (using Python's unicodedata.normalize()) version.
        Must be called in app context and uses
        :py:data:`SECURITY_INPUT_NORMALIZE_FORM` and
        :py:data:`SECURITY_USERNAME_ALLOWED_CHARS` config variables.
        """
        reason, clean_input = input_svn(
            username, cv("USERNAME_ALLOWED_CHARS"), cv("INPUT_NORMALIZE_FORM")
        )
        return clean_input

    def validate(self, username: str) -> tuple[str | None, str | None]:
        """
        Username validation.
        Called in app/request context.

        The username is first validated then normalized.
        Return value is a tuple (msg, normalized_username). msg will be None if
        properly validated.

        It is important that None be returned if data is an empty string since
        otherwise DBs will complain since the field is unique/nullable.
        """
        if not username:
            return None, None
        reason, clean_input = input_svn(
            username, cv("USERNAME_ALLOWED_CHARS"), cv("INPUT_NORMALIZE_FORM")
        )
        if clean_input is None:
            msg = (
                "USERNAME_DISALLOWED_CHARACTERS"
                if reason == "unallowed"
                else "INVALID_INPUT"
            )
            return get_message(msg)[0], None
        umin = cv("USERNAME_MIN_LENGTH")
        umax = cv("USERNAME_MAX_LENGTH")
        if len(clean_input) < umin or len(clean_input) > umax:
            return (
                get_message("USERNAME_INVALID_LENGTH", min=umin, max=umax)[0],
                clean_input,
            )
        return None, clean_input
