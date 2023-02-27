"""
    flask_security.oauth_glue
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Class and methods to glue our login path with authlib for to support 'social' auth.

    :copyright: (c) 2022-2022 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

"""

import typing as t
from typing import Any

try:
    from authlib.integrations.flask_client import OAuth
    from authlib.integrations.base_client.errors import (
        MismatchingStateError,
        OAuthError,
    )
except ImportError:  # pragma: no cover
    pass

from flask import abort, after_this_request, redirect, request

from .proxies import _security
from .utils import (
    config_value as cv,
    do_flash,
    login_user,
    get_message,
    get_post_login_redirect,
    get_url,
    propagate_next,
    slash_url_suffix,
    url_for_security,
    view_commit,
)

if t.TYPE_CHECKING:  # pragma: no cover
    import flask
    from flask.typing import ResponseValue

CbType = t.Callable[["OAuth", str], t.Tuple[str, t.Any]]


GITHUB = dict(
    access_token_url="https://github.com/login/oauth/access_token",
    access_token_params=None,
    authorize_url="https://github.com/login/oauth/authorize",
    authorize_params=None,
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "user:email"},
)


def github_fetch_identity(oauth: "OAuth", token: str) -> t.Tuple[str, t.Any]:
    resp = oauth.github.get("user", token=token)
    profile = resp.json()
    return "email", profile["email"]


GOOGLE = dict(
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


def google_fetch_identity(
    oauth: "OAuth", token: t.Any
) -> t.Tuple[str, t.Any]:  # pragma no cover
    profile = token["userinfo"]
    return "email", profile["email"]


def oauthstart(name: str) -> "ResponseValue":
    """View to start an oauth authentication.
    Name is a pre-registered oauth provider.
    TODO: remember me?
    """
    assert _security.oauthglue
    # we never want to return here or to the redirect location.
    values = dict(next=request.args.get("next", "/"))
    return _security.oauthglue.get_redirect(name, **values)


def oauthresponse(name: str) -> "ResponseValue":
    """Callback from oauth provider - response is provider specific"""
    assert _security.oauthglue
    oauth_provider = _security.oauthglue.oauth_provider(name)
    if not oauth_provider:
        # this shouldn't really be able to happen
        abort(404)
    # This parses the Flask Request
    try:
        token = oauth_provider.authorize_access_token()
    except (MismatchingStateError, OAuthError):
        """One known way this can happen is if the session cookie 'samesite'
        is set to 'strict' and e.g. the first time the user goes to github
        and has to authorize this app and then redirect - the session
        cookie isn't sent - and by default that is where the state is kept.
        """
        # N.B. flashing doesn't seem to work - probably for same reason as
        # the original failure...
        m, c = get_message("OAUTH_HANDSHAKE_ERROR")
        if _security.redirect_behavior == "spa":
            return redirect(get_url(cv("LOGIN_ERROR_VIEW"), qparams={c: m}))
        do_flash(m, c)
        return redirect(url_for_security("login"))

    field_name, value = _security.oauthglue._oauth_response(name, token)
    user = _security.datastore.find_user(**{field_name: value})
    if user:
        after_this_request(view_commit)
        response = _security.two_factor_plugins.tf_enter(
            user, False, "oauth", next_loc=propagate_next(request.url)
        )
        if response:
            return response
        # two factor not required - login user
        login_user(user)
        if _security.redirect_behavior == "spa":
            return redirect(
                get_url(cv("POST_LOGIN_VIEW"), qparams=user.get_redirect_qparams())
            )
        return redirect(get_post_login_redirect())
    # Seems ok to show identity - the only identity it could be is the callers
    # so seems no way this can be used to enumerate registered users.
    m, c = get_message("IDENTITY_NOT_REGISTERED", id=value)
    if _security.redirect_behavior == "spa":
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
    using app.security.oauthglue.register_provider().

    See `Flask OAuth Client <https://docs.authlib.org/en/latest/client/flask.html>`_

    .. versionadded:: 5.1.0
    """

    def __init__(self, app: "flask.Flask", oauthapp: t.Optional["OAuth"] = None):
        if not oauthapp:
            oauthapp = OAuth(app)
        self.oauth = oauthapp
        self.providers: t.Dict[str, t.Dict[str, CbType]] = dict()
        if cv("OAUTH_BUILTIN_PROVIDERS", app=app):
            for provider in cv("OAUTH_BUILTIN_PROVIDERS", app=app):
                if provider == "github":
                    self.register_provider("github", GITHUB, github_fetch_identity)
                elif provider == "google":
                    self.register_provider("google", GOOGLE, google_fetch_identity)

    def _create_blueprint(self, app: "flask.Flask", bp: "flask.Blueprint") -> None:
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

    def get_redirect(self, name: str, **values: t.Any) -> "ResponseValue":
        oauth_provider = self.oauth_provider(name)
        if not oauth_provider:
            return abort(404)
        start_uri = url_for_security(
            "oauthresponse", name=name, _external=True, **values
        )
        redirect_url = oauth_provider.authorize_redirect(start_uri)
        return redirect_url

    @property
    def provider_names(self):
        return self.providers.keys()

    @property
    def oauth_app(self):
        return self.oauth

    def oauth_provider(self, name):
        return getattr(self.oauth, name, None)

    def register_provider(
        self,
        name: str,
        registration_info: t.Optional[t.Dict[str, t.Any]],
        fetch_identity_cb: CbType,
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

        """
        self.providers[name] = dict(cb=fetch_identity_cb)
        if registration_info:
            self.oauth.register(name, **registration_info)

    def _oauth_response(self, name: str, token: str) -> t.Tuple[str, Any]:
        return self.providers[name]["cb"](self.oauth, token)
