"""
    flask_security.oauth_provider
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Class and methods to create providers for oauth_glue.
    Example providers for github and google.

    :copyright: (c) 2024-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

"""

from __future__ import annotations
import collections.abc as cabc

try:
    from authlib.integrations.flask_client import OAuth
    from authlib.integrations.base_client.errors import (
        OAuthError,
    )
except ImportError:  # pragma: no cover
    pass

import typing as t

from flask import redirect

from .utils import (
    config_value as cv,
    do_flash,
    get_message,
    get_url,
    url_for_security,
)

if t.TYPE_CHECKING:  # pragma: no cover
    from flask.typing import ResponseValue

OauthCbType = cabc.Callable[["OAuth", t.Any], tuple[str, t.Any]]


class FsOAuthProvider:
    """
    Subclass this or instantiate to add new oauth providers.

    Subclassing allows for customizing additional aspects of the oauth flow
    in particular - a custom error path for oauth flow state mismatches and
    other errors thrown by authlib.

    Call security.oauthglue.register_provider_ext(myproviderclass("myprovider"))

    :param name: a name for provider - must match what was passed if this
     is already registered with Oauth.
    :param registration_info: This dict is passed directly to Oauth as
     part of registration - not needed if provider already registered with
     Oauth
    :param fetch_identity_cb: Call back from response to oauth flow.
    """

    def __init__(
        self,
        name: str,
        registration_info: dict[str, t.Any] | None = None,
        fetch_identity_cb: OauthCbType | None = None,
    ):
        self.name = name
        self._registration_info = registration_info or {}
        self._fetch_identity_cb = fetch_identity_cb

    def authlib_config(self) -> dict[str, t.Any]:
        """Return dict with authlib configuration.
        This is called as part of provider registration."""
        return self._registration_info

    def fetch_identity_cb(self, oauth: OAuth, token: t.Any) -> tuple[str, t.Any]:
        """This callback is called when the oauth
        redirect happens. It must take the response from the provider and return
        a tuple of <user_model_field_name, value> - which will be used
        to look up the user in the datastore."""
        if not self._fetch_identity_cb:  # pragma no cover
            raise NotImplementedError
        return self._fetch_identity_cb(oauth, token)

    def oauth_response_failure(self, e: OAuthError) -> ResponseValue:
        """Called if authlib authorize_access_token throws an error.

        N.B. flashing doesn't seem to work in some cases - if the session
        cookie has samesite='strict' and it is the first registration.
        """
        m, c = get_message(
            "OAUTH_HANDSHAKE_ERROR", exerror=e.error, exdesc=e.description
        )
        if cv("REDIRECT_BEHAVIOR") == "spa":
            return redirect(get_url(cv("LOGIN_ERROR_VIEW"), qparams={c: m}))
        do_flash(m, c)
        return redirect(url_for_security("login"))


class GitHubFsOauthProvider(FsOAuthProvider):
    def authlib_config(self):
        return dict(
            access_token_url="https://github.com/login/oauth/access_token",
            access_token_params=None,
            authorize_url="https://github.com/login/oauth/authorize",
            authorize_params=None,
            api_base_url="https://api.github.com/",
            client_kwargs={"scope": "user:email"},
        )

    def fetch_identity_cb(self, oauth, token):
        resp = oauth.github.get("user", token=token)
        profile = resp.json()
        return "email", profile["email"]


class GoogleFsOauthProvider(FsOAuthProvider):
    def authlib_config(self):
        return dict(
            server_metadata_url="https://accounts.google.com/"
            ".well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    def fetch_identity_cb(self, oauth, token):  # pragma no cover
        profile = token["userinfo"]
        return "email", profile["email"]
