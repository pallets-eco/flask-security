"""
    flask_security.webauthn_util
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Utility class providing methods controlling various aspects of webauthn.

    :copyright: (c) 2020-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

"""

from __future__ import annotations

import secrets
import typing as t

from flask import current_app, request

try:
    # noinspection PyUnresolvedReferences
    from webauthn.helpers.structs import (
        AuthenticatorAttachment,
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )
except ImportError:  # pragma: no cover
    pass


if t.TYPE_CHECKING:  # pragma: no cover
    import flask
    from .datastore import User


class WebauthnUtil:
    """
    Utility class allowing an application to fine-tune various Relying Party
    attributes.

    To provide your own implementation, pass in the class as ``webauthn_util_cls``
    at init time.  Your class will be instantiated once as part of app initialization.

    .. versionadded:: 5.0.0
    """

    def __init__(self, app: flask.Flask):
        """Instantiate class.

        :param app: The Flask application being initialized.
        """
        pass

    def generate_challenge(self, nbytes: int | None = None) -> str:
        # Mostly override this for testing, so we can have a 'constant' challenge.
        return secrets.token_urlsafe(nbytes)

    def origin(self) -> str:
        # Return the RP origin - normally this is just the URL of the application.
        return request.host_url.rstrip("/")

    def registration_options(
        self, user: User, usage: str, existing_options: dict[str, t.Any]
    ) -> dict[str, t.Any]:
        """
        :param user: User object - could be used to configure on a per-user basis.
        :param usage: Either "first" or "secondary" (webauthn is being used as a second
            factor for authentication)
        :param existing_options: Currently filled in registration options.

        Return a dict that will be sent in to py-webauthn generate_registration_options
        """
        existing_options["authenticator_selection"] = self.authenticator_selection(
            user, usage
        )
        return existing_options

    def authenticator_selection(
        self, user: User, usage: str
    ) -> AuthenticatorSelectionCriteria:
        """
        :param user: User object - could be used to configure on a per-user basis.
        :param usage: Either "first" or "secondary" (webauthn is being used as a second
            factor for authentication

        Part of the registration ceremony is providing information about what kind
        of authenticators the app is interested in.
        See: https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictionary-authenticatorSelection

        The main options are:
            - whether you want a ResidentKey (discoverable)
            - Attachment - platform or cross-platform
            - Does the key have to provide user-verification

        :note::
            If the key isn't resident then it isn't discoverable which means that
            the user won't be able to use that key unless they identify themselves
            (use the key as a second factor OR type in their identity). If they are forced
            to type in their identity PRIOR to being authenticated, then there is the
            possibility that the app will leak username information.
        """  # noqa: E501

        select_criteria = AuthenticatorSelectionCriteria()
        # TODO: look at #sctn-usecase-new-device-registration to see a reason
        # to allow multiple keys as "first" - only one would need to be cross-platform
        if usage == "first":
            select_criteria.authenticator_attachment = (
                AuthenticatorAttachment.CROSS_PLATFORM
            )
            select_criteria.user_verification = UserVerificationRequirement.PREFERRED
        else:
            # For second factor minimize user-interaction by not asking for UV
            select_criteria.user_verification = UserVerificationRequirement.DISCOURAGED

        if not current_app.config.get("SECURITY_WAN_ALLOW_USER_HINTS"):
            select_criteria.resident_key = ResidentKeyRequirement.REQUIRED
        else:
            select_criteria.resident_key = ResidentKeyRequirement.PREFERRED
        return select_criteria

    def authentication_options(
        self,
        user: User | None,
        usage: list[str],
        existing_options: dict[str, t.Any],
    ) -> dict[str, t.Any]:
        """
        :param user: User object - could be used to configure on a per-user basis.
            However, this can be null.
        :param usage: Either "first" or "secondary" (webauthn is being used as a second
            factor for authentication)
        :param existing_options: Currently filled in authentication options.

        Return a dict that will be sent in to
         py-webauthn generate_authentication_options
        """
        existing_options["user_verification"] = self.user_verification(user, usage)
        return existing_options

    def user_verification(
        self, user: User | None, usage: list[str]
    ) -> UserVerificationRequirement:
        """
        As part of signin - do we want/need user verification.
        This is called from /wan-signin and /wan-verify

        :param user: User object - could be used to configure on a per-user basis.
            Note that this may not be set on initial wan-signin.
        :param usage: List of  "first", "secondary" (webauthn is being used as a second
            factor for authentication). Note that in the ``verify``/``reauthentication``
            case this list is derived from :py:data:`SECURITY_WAN_ALLOW_AS_VERIFY`

        """
        if "secondary" in usage:
            return UserVerificationRequirement.DISCOURAGED
        if current_app.config.get("SECURITY_WAN_ALLOW_AS_MULTI_FACTOR"):
            return UserVerificationRequirement.PREFERRED
        return UserVerificationRequirement.PREFERRED
