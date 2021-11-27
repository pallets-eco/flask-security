"""
    flask_security.webauthn_util
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Utility class providing methods controlling various aspects of webauthn.

    :copyright: (c) 2020-2021 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

"""

import secrets
import typing as t

from flask import request

try:
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
    )
except ImportError:
    pass


if t.TYPE_CHECKING:  # pragma: no cover
    import flask
    from .datastore import User


class WebauthnUtil:
    def __init__(self, app: "flask.Flask"):
        """Instantiate class.

        :param app: The Flask application being initialized.
        """
        pass

    def generate_challenge(self, nbytes: t.Optional[int] = None) -> str:
        # Mostly override this for testing so we can have a 'constant' challenge.
        return secrets.token_urlsafe(nbytes)

    def origin(self) -> str:
        # Return the RP origin - normally this is just the URL of the application.
        return request.host_url.rstrip("/")

    def authenticator_selection(self, user: "User") -> "AuthenticatorSelectionCriteria":
        """
        Part of the registration ceremony is providing information about what kind
        of authenticators the app is interested in.
        See: https://www.w3.org/TR/2021/REC-webauthn-2-20210408
        /#dictionary-authenticatorSelection

        Simply - if the key isn't resident then it isn't discoverable which means that
        the user won't be able to use that key unless they identify themselves
        (use the key as a second factor OR type in their identity). If they are forced
        to type in their identity PRIOR to be authenticated, then there is the
        possibility that the app will leak username information.
        """
        return AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED
        )
