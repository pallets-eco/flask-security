"""
    flask_security.oauth_glue
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Class and methods to glue our login path with authlib for to support 'social' auth.

    :copyright: (c) 2022-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

"""

from __future__ import annotations

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

from .decorators import unauth_csrf
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


@unauth_csrf()
def oauthstart(name: str) -> ResponseValue:
    """View to start an oauth authentication.
    Name is a pre-registered oauth provider.
    TODO: remember me?
    """
    assert _security.oauthglue
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
    return _security.oauthglue.get_redirect(name)


def oauthresponse(name: str) -> ResponseValue:
    """
    Callback from oauth provider - response is provider specific
    Since this is a callback from oauth provider - there is no form,
    We may have stored the original 'next' in the session
    N.B. all responses MUST be redirects.
    """
    assert _security.oauthglue
    authlib_provider = _security.oauthglue.authlib_provider(name)
    oauth_provider = _security.oauthglue.providers.get(name)
    if not authlib_provider or not oauth_provider:
        # this should only happen with purposeful bad API call
        abort(404)  # TODO - redirect... to where?
    # This parses the Flask Request
    try:
        token = authlib_provider.authorize_access_token()
    except OAuthError as e:
        """One known way this can happen is if the session cookie 'samesite'
        is set to 'strict' and e.g. the first time the user goes to github
        and has to authorize this app and then redirect - the session
        cookie isn't sent - and by default that is where the state is kept.
        """
        return oauth_provider.oauth_response_failure(e)

    field_name, value = oauth_provider.fetch_identity_cb(
        _security.oauthglue.oauth_app, token
    )
    user = _security.datastore.find_user(**{field_name: value})
    if user:
        after_this_request(view_commit)
        next_loc = session.pop("fs_oauth_next", None)
        response = _security.two_factor_plugins.tf_enter(
            user, False, "oauth", next_loc=next_loc
        )
        if response:
            return response
        # two factor not required - login user
        login_user(user)
        if cv("REDIRECT_BEHAVIOR") == "spa":
            return redirect(
                get_url(
                    cv("POST_OAUTH_LOGIN_VIEW"), qparams=user.get_redirect_qparams()
                )
            )
        redirect_url = get_post_action_redirect(
            "SECURITY_POST_LOGIN_VIEW", dict(next=next_loc)
        )
        return redirect(redirect_url)
    # Seems ok to show identity - the only identity it could be is the callers
    # so seems no way this can be used to enumerate registered users.
    m, c = get_message("IDENTITY_NOT_REGISTERED", id=value)
    if cv("REDIRECT_BEHAVIOR") == "spa":
        return redirect(get_url(cv("LOGIN_ERROR_VIEW"), qparams={c: m}))
    do_flash(m, c)
    # TODO: should redirect to where we came from?
    return redirect(url_for_security("login"))


class OAuthGlue:
    """
    Provide the necessary glue between the Flask-Security login process and
    authlib oauth client code.

    There are some builtin providers which can be used or not - configured via
    :py:data:`SECURITY_OAUTH_BUILTIN_PROVIDERS`. Any other provider can be registered
    using :py:meth:`register_provider_ext`.

    See `Flask OAuth Client <https://docs.authlib.org/en/latest/client/flask.html>`_

    .. versionadded:: 5.1.0

    .. versionchanged:: 5.4.0
        Added register_provider_ext which allows applications more control to
        manage new providers (such as extended error handling).
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

    def get_redirect(self, name: str, **values: t.Any) -> ResponseValue:
        authlib_provider = self.authlib_provider(name)
        if not authlib_provider:
            return abort(404)
        start_uri = url_for_security(
            "oauthresponse", name=name, _external=True, **values
        )
        redirect_url = authlib_provider.authorize_redirect(start_uri)
        return redirect_url

    @property
    def provider_names(self):
        return self.providers.keys()

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
