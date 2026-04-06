"""
flask_security.oauth_glue
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Class and methods to glue our login path with authlib for to support 'social' auth.

:copyright: (c) 2022-2026 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.

"""

from __future__ import annotations

import time
import typing as t

try:
    # noinspection PyUnresolvedReferences
    from authlib.integrations.flask_client import OAuth

    # noinspection PyUnresolvedReferences
    from authlib.integrations.base_client.errors import (
        OAuthError,
    )
except ImportError:  # pragma: no cover
    pass

from flask import abort, after_this_request, redirect, request, session
from flask_login import current_user

from .decorators import auth_required, unauth_csrf
from .oauth_provider import (
    OauthCbType,
    FsOAuthProvider,
    GoogleFsOauthProvider,
    GitHubFsOauthProvider,
)
from .proxies import _security
from .utils import (
    config_value as cv,
    do_flash,
    login_user,
    get_message,
    get_post_action_redirect,
    get_url,
    is_user_authenticated,
    json_error_response,
    slash_url_suffix,
    url_for_security,
    view_commit,
)

if t.TYPE_CHECKING:  # pragma: no cover
    import flask
    from flask.typing import ResponseValue
    from flask_security import UserMixin


@unauth_csrf()
def oauthstart(name: str) -> ResponseValue:
    """View to start an OAuth authentication.
    Name is a pre-registered OAuth provider.
    TODO: remember me?
    """
    assert _security.oauthglue is not None
    if is_user_authenticated(current_user):
        # Just redirect current_user to POST_LOGIN_VIEW.
        # For json - return an error.
        # This endpoint is POST only.
        # This does NOT use get_post_login_redirect() so that it doesn't look at
        # 'next' - which can cause infinite redirect loops
        # (see test_common::test_authenticated_loop)
        if _security._want_json(request):
            payload = json_error_response(
                errors=get_message("ANONYMOUS_USER_REQUIRED")[0]
            )
            return _security._render_json(payload, 400, None, None)
        else:
            return redirect(get_url(cv("POST_LOGIN_VIEW")))
    # we never want to return here or to the redirect location.
    # Some providers match on entire redirect url - so we don't want to
    # store next there. Use session.
    session.pop("fs_oauth_next", None)
    if request.args.get("next"):
        session["fs_oauth_next"] = request.args.get("next")
    return _security.oauthglue.get_redirect(name, "oauthresponse")


def _oauth_response_common(name: str) -> tuple[t.Any, UserMixin | None] | t.NoReturn:
    """
    Common code for oauth response (login or verify)
    This can abort or raise an OAuthError or return a
    tuple of (field_value, user)
    """
    assert _security.oauthglue is not None
    authlib_provider = _security.oauthglue.authlib_provider(name)
    oauth_provider = _security.oauthglue.providers.get(name)
    if not authlib_provider or not oauth_provider:
        # this should only happen with purposeful bad API call
        abort(404)  # TODO - redirect... to where?
    # This parses the Flask Request and can raise an OAuthError
    token = authlib_provider.authorize_access_token()

    field_name, field_value = oauth_provider.fetch_identity_cb(
        _security.oauthglue.oauth_app, token
    )
    user = _security.datastore.find_user(**{field_name: field_value})
    return field_value, user


def oauthresponse(name: str) -> ResponseValue:
    """
    Callback from oauth provider - response is provider specific
    Since this is a callback from oauth provider - there is no form,
    We may have stored the original 'next' in the session
    N.B. all responses MUST be redirects.
    """
    assert _security.oauthglue is not None
    oauth_provider = _security.oauthglue.providers.get(name)
    try:
        field_value, user = _oauth_response_common(name)
    except OAuthError as e:
        """One known way this can happen is if the session cookie 'samesite'
        is set to 'strict' and e.g. the first time the user goes to github
        and has to authorize this app and then redirect - the session
        cookie isn't sent - and by default that is where the state is kept.
        """
        assert oauth_provider is not None
        return oauth_provider.oauth_response_failure("LOGIN_ERROR_VIEW", e)
    form_error: list[str] = []
    if user and user.is_active and user.is_allowed_authn(form_error):
        after_this_request(view_commit)
        next_loc = session.pop("fs_oauth_next", None)
        response = _security.two_factor_plugins.tf_enter(
            user, False, "oauth", next_loc=next_loc
        )
        if response:
            return response
        # two-factor not required - login user
        login_user(user, authn_via=["oauth"])
        if cv("REDIRECT_BEHAVIOR") == "spa":
            redirect_url = get_url(
                cv("POST_OAUTH_LOGIN_VIEW"), qparams=user.get_redirect_qparams()
            )
        else:
            redirect_url = get_post_action_redirect(
                "SECURITY_POST_LOGIN_VIEW", dict(next=next_loc)
            )
        return redirect(redirect_url)
    # Seems ok to show identity - the only identity it could be is the callers
    # so seems no way this can be used to enumerate registered users.
    if user and not user.is_active:
        m, c = get_message("DISABLED_ACCOUNT")
    elif form_error:
        m = form_error[0]
        c = "error"
    else:
        m, c = get_message("IDENTITY_NOT_REGISTERED", id=field_value)
    if cv("REDIRECT_BEHAVIOR") == "spa":
        return redirect(get_url(cv("LOGIN_ERROR_VIEW"), qparams={c: m}))
    do_flash(m, c)
    # TODO: should redirect to where we came from?
    return redirect(url_for_security("login"))


@auth_required(lambda: cv("API_ENABLED_METHODS"))
def oauth_verify_start(name: str) -> ResponseValue:
    """
    Re-authenticate to reset freshness time.
    With a forms-based app this is the result of a reauthn_handler redirect.
    """
    # we never want to return here or to the redirect location.
    # Some providers match on entire redirect url - so we don't want to
    # store next there. Use session.
    assert _security.oauthglue is not None
    session.pop("fs_oauth_next", None)
    if request.args.get("next"):
        session["fs_oauth_next"] = request.args.get("next")
    return _security.oauthglue.get_redirect(name, "oauth_verify_response")


def oauth_verify_response(name: str) -> ResponseValue:
    """
    Callback from oauth provider - response is provider-specific
    Since this is a callback from oauth provider - there is no form,
    We may have stored the original 'next' in the session
    N.B. all responses MUST be redirects.
    """
    assert _security.oauthglue is not None
    oauth_provider = _security.oauthglue.providers.get(name)
    try:
        field_value, user = _oauth_response_common(name)
    except OAuthError as e:
        """One known way this can happen is if the session cookie 'samesite'
        is set to 'strict' and e.g. the first time the user goes to github
        and has to authorize this app and then redirect - the session
        cookie isn't sent - and by default that is where the state is kept.
        """
        assert oauth_provider is not None
        return oauth_provider.oauth_response_failure("VERIFY_ERROR_VIEW", e)
    next_loc = session.pop("fs_oauth_next", None)
    if user:
        # verified - so set freshness time.
        session["fs_paa"] = time.time()
        if cv("REDIRECT_BEHAVIOR") == "spa":
            redirect_url = get_url(
                cv("POST_OAUTH_VERIFY_VIEW"), qparams=user.get_redirect_qparams()
            )
        else:
            do_flash(*get_message("REAUTHENTICATION_SUCCESSFUL"))
            redirect_url = get_post_action_redirect(
                "SECURITY_POST_VERIFY_VIEW", dict(next=next_loc)
            )
        return redirect(redirect_url)

    m, c = get_message("IDENTITY_NOT_REGISTERED", id=field_value)
    if cv("REDIRECT_BEHAVIOR") == "spa":
        return redirect(get_url(cv("VERIFY_ERROR_VIEW"), qparams={c: m}))
    do_flash(m, c)
    # Go back to verify - this is the same logic as in default_reauthn_handler
    view = "us_verify" if cv("UNIFIED_SIGNIN") else "verify"
    return redirect(url_for_security(view, next=next_loc))


class OAuthGlue:
    """
    Provide the necessary glue between the Flask-Security login process and
    authlib oauth client code.

    There are some builtin providers that can be used or not - configured via
    :py:data:`SECURITY_OAUTH_BUILTIN_PROVIDERS`. Any other provider can be registered
    using :py:meth:`register_provider_ext`.

    See `Flask OAuth Client <https://docs.authlib.org/en/latest/client/flask.html>`_

    .. versionadded:: 5.1.0

    .. versionchanged:: 5.4.0
        Added register_provider_ext which allows applications more control to
        manage new providers (such as extended error handling).

    .. versionchanged:: 5.8.0
        Added endpoints for verify using OAuth.
    """

    def __init__(self, app: flask.Flask, oauthapp: OAuth | None = None):
        if not oauthapp:
            oauthapp = OAuth(app)
        self.oauth = oauthapp
        self.providers: dict[str, FsOAuthProvider] = dict()
        if cv("OAUTH_BUILTIN_PROVIDERS", app=app):
            for provider in cv("OAUTH_BUILTIN_PROVIDERS", app=app):
                if provider == "github":
                    self.register_provider_ext(GitHubFsOauthProvider("github"))
                elif provider == "google":
                    self.register_provider_ext(GoogleFsOauthProvider("google"))

    def _create_blueprint(self, app: flask.Flask, bp: flask.Blueprint) -> None:
        # Routes for each type of oauth provider
        start_url = cv("OAUTH_START_URL", app=app)
        response_url = cv("OAUTH_RESPONSE_URL", app=app)
        bp.route(
            start_url + slash_url_suffix(start_url, "<name>"),
            methods=["POST"],
            endpoint="oauthstart",
        )(oauthstart)
        bp.route(
            response_url + slash_url_suffix(response_url, "<name>"),
            methods=["GET"],
            endpoint="oauthresponse",
        )(oauthresponse)

        if cv("FRESHNESS", app=app).total_seconds() >= 0:
            verify_start_url = cv("OAUTH_VERIFY_START_URL", app=app)
            bp.route(
                verify_start_url + slash_url_suffix(verify_start_url, "<name>"),
                methods=["POST"],
                endpoint="oauth_verify_start",
            )(oauth_verify_start)
            verify_response_url = cv("OAUTH_VERIFY_RESPONSE_URL", app=app)
            bp.route(
                verify_response_url + slash_url_suffix(verify_response_url, "<name>"),
                methods=["GET"],
                endpoint="oauth_verify_response",
            )(oauth_verify_response)

    def get_redirect(
        self, name: str, endpoint: str, **values: t.Any
    ) -> ResponseValue | t.NoReturn:
        authlib_provider = self.authlib_provider(name)
        if not authlib_provider:
            abort(404)
        start_uri = url_for_security(endpoint, name=name, _external=True, **values)
        redirect_url = authlib_provider.authorize_redirect(start_uri)
        return redirect_url

    @property
    def provider_names(self) -> list[str]:
        return list(self.providers.keys())

    @property
    def oauth_app(self):
        return self.oauth

    def authlib_provider(self, name):
        return getattr(self.oauth, name, None)

    def register_provider(
        self,
        name: str,
        registration_info: dict[str, t.Any] | None,
        fetch_identity_cb: OauthCbType,
    ) -> None:
        """Add a provider to the list.

        :param name: Name of provider. This is used as part of the
         :py:data:`SECURITY_OAUTH_START_URL`.
        :param registration_info: Sent directly to authlib. Set this to None
         if you already have registered the provider directly with OAuth.
        :param fetch_identity_cb: This callback is called when the oauth
         redirect happens. It must take the response from the provider and return
         a tuple of <user_model_field_name, value> - which will be used
         to look up the user in the datastore.

        The provider can be registered with OAuth here or already be done by the
        application. If you register directly with OAuth make sure to use
        the same `name`.

        .. deprecated:: 5.4.0
            Use :py:meth:`register_provider_ext` instead.

        """
        pcls = FsOAuthProvider(
            name,
            registration_info=registration_info,
            fetch_identity_cb=fetch_identity_cb,
        )
        self.register_provider_ext(pcls)

    def register_provider_ext(self, provider: FsOAuthProvider) -> None:
        """Register a provider via an instance of subclass.
        This is the new way - to provide more control for applications

        The authlib provider can be registered here (by calling Oauth)
        or already be done by the application.
        If you register directly with OAuth make sure to use
        the same `name` when instantiating the class.
        """
        self.providers[provider.name] = provider
        if not self.authlib_provider(provider.name):
            self.oauth.register(provider.name, **provider.authlib_config())
