"""
    flask_security.decorators
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security decorators module

    :copyright: (c) 2012-2019 by Matt Wright.
    :copyright: (c) 2019-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from __future__ import annotations

from collections import namedtuple
import datetime
from functools import wraps
import typing as t

from flask import Response, abort, current_app, g, redirect, request
from flask_login import current_user, login_required  # noqa: F401
from flask_principal import Identity, Permission, RoleNeed, identity_changed
from flask_wtf.csrf import CSRFError
from werkzeug.local import LocalProxy

from .proxies import _security, DecoratedView
from .signals import user_unauthenticated
from .utils import (
    FsPermNeed,
    config_value as cv,
    do_flash,
    get_message,
    get_url,
    is_user_authenticated,
    lookup_identity,
    check_and_update_authn_fresh,
    json_error_response,
    set_request_attr,
    simplify_url,
    get_request_attr,
    url_for_security,
)

if t.TYPE_CHECKING:  # pragma: no cover
    from flask.typing import ResponseValue

# Convenient references
_csrf = LocalProxy(lambda: current_app.extensions["csrf"])

BasicAuth = namedtuple("BasicAuth", "username, password")

# NOTE: this is here for backwards compatibility, it is deprecated and
# could be removed any time!
_default_unauthenticated_html = """
    <h1>Unauthorized</h1>
    <p>The server could not verify that you are authorized to access the URL
    requested. You either supplied the wrong credentials (e.g. a bad password),
    or your browser doesn't understand how to supply the credentials required.
    </p>
    """


def _get_unauthenticated_response(text=None, headers=None):
    text = text or _default_unauthenticated_html
    headers = headers or {}
    return Response(text, 401, headers)


def default_unauthn_handler(mechanisms=None, headers=None):
    """Default callback for failures to authenticate

    If caller wants JSON - return 401.
    If caller wants BasicAuth - return 401 (the WWW-Authenticate header is set).
    Otherwise - assume caller is html and redirect if possible to a login view.
    """
    user_unauthenticated.send(
        current_app._get_current_object(),  # type: ignore[attr-defined]
        _async_wrapper=current_app.ensure_sync,
    )
    headers = headers or {}
    m, c = get_message("UNAUTHENTICATED")

    if cv("BACKWARDS_COMPAT_UNAUTHN"):
        return _get_unauthenticated_response(headers=headers)
    if _security._want_json(request):
        payload = json_error_response(errors=m)
        return _security._render_json(payload, 401, headers, None)

    # Basic-Auth is often used to provide a browser based login form and then the
    # browser will always add the BasicAuth credentials. For that to work we need to
    # return 401 and not redirect to our login view.
    if "WWW-Authenticate" in headers:
        return Response(m, 401, headers)

    do_flash(m, c)
    # Simplify the original URL to be relative (if possible) and set as 'next' parameter
    login_url = url_for_security("login", _external=True)
    next_url = simplify_url(login_url, request.url)
    redirect_url = url_for_security("login", next=next_url)
    return redirect(redirect_url)


def default_reauthn_handler(within, grace):
    """Default callback for 'freshness' related authn failures.

    If caller wants JSON - return 401
    Otherwise - assume caller is html and redirect if possible to configured view.

    """
    m, c = get_message("REAUTHENTICATION_REQUIRED")

    if _security._want_json(request):
        from .webauthn import has_webauthn

        is_us = cv("UNIFIED_SIGNIN")
        payload = json_error_response(errors=m)
        payload["reauth_required"] = True
        payload["unified_signin_enabled"] = is_us
        payload["has_webauthn_verify_credential"] = has_webauthn(
            current_user, cv("WAN_ALLOW_AS_VERIFY")
        )
        return _security._render_json(payload, 401, None, None)

    view = "us_verify" if cv("UNIFIED_SIGNIN") else "verify"
    do_flash(m, c)
    # Simplify the original URL to be relative (if possible) and set as 'next' parameter
    view_url = url_for_security(view, _external=True)
    next_url = simplify_url(view_url, request.url)
    redirect_url = url_for_security(view, next=next_url)
    return redirect(redirect_url)


def default_unauthz_handler(func_name, params):
    unauthz_message, unauthz_message_type = get_message("UNAUTHORIZED")
    if _security._want_json(request):
        payload = json_error_response(errors=unauthz_message)
        return _security._render_json(payload, 403, None, None)
    if view := cv("UNAUTHORIZED_VIEW"):
        if callable(view):
            if not (redirect_to := view()):
                abort(403)
        else:
            redirect_to = get_url(view)
        do_flash(unauthz_message, unauthz_message_type)
        return redirect(redirect_to)
    abort(403)


def _check_token():
    user = _security.login_manager.request_callback(request)
    if is_user_authenticated(user):
        identity_changed.send(
            current_app._get_current_object(),
            _async_wrapper=current_app.ensure_sync,
            identity=Identity(user.fs_uniquifier),
        )
        return True

    return False


def _check_session():
    """
    Note that flask_login will have already run _load_user (due to someone referencing
    current_user proxy). This will have called our _user_loader or _request_loader
    already.
    This method needs to determine whether the authenticated user was authenticated
    due to _user_loader or _request_loader and return True for the former.
    This routine makes sure that if an endpoint is decorated with just allowing
    'session' that token authentication won't return True (even though the user
    is in fact correctly authenticated). There are certainly endpoints that need to
    be web browser/session only (often those that in fact return tokens!).
    """
    if not is_user_authenticated(current_user):
        return False
    if get_request_attr("fs_authn_via") != "session":
        return False
    return True


def _check_http_auth():
    auth = request.authorization or BasicAuth(username=None, password=None)
    if not auth.username:
        return False
    user = lookup_identity(auth.username)
    if user and not user.active:
        return False

    if user and user.verify_and_update_password(auth.password):
        _security.datastore.commit()
        _security.login_manager._update_request_context_with_user(user)
        identity_changed.send(
            current_app._get_current_object(),
            _async_wrapper=current_app.ensure_sync,
            identity=Identity(user.fs_uniquifier),
        )
        return True

    return False


def handle_csrf(method: str, json_response: bool = False) -> ResponseValue | None:
    """Invoke CSRF protection based on authentication method.

    Usually this is called as part of a decorator, but if that isn't
    appropriate, endpoint code can call this directly.

    If CSRF protection is appropriate, this will call flask_wtf::protect() which
    will raise a CSRFError(BadRequest) on CSRF failure.

    This routine does nothing if any of these are true:

        #) *WTF_CSRF_ENABLED* is set to False

        #) the Flask-WTF CSRF module hasn't been initialized

        #) csrfProtect already checked and accepted the token

    This means in the default config - CSRF is done as part of form validation
    not here. Only if the application calls CSRFProtect(app) will this method
    do anything. Furthermore - since this is called PRIOR to form instantiation
    if the request is JSON - it MUST send the csrf_token as a header.

    If the passed in method is not in
    :py:data:`SECURITY_CSRF_PROTECT_MECHANISMS` then in addition to
    no CSRF code being run, the flask_wtf request global 'csrf_valid' will be set
    so that downstream code knows to ignore any CSRF checks.

    Returns None if all ok, returns a Response with JSON error if request
    wanted JSON - else re-raises the CSRFError exception.

    .. versionadded:: 3.3.0

    .. versionchanged:: 5.4.3
        Use flask_wtf request global 'csrf_valid' instead of our own to handle
        application forms that aren't derived from our forms.
    """
    if (
        not current_app.config.get("WTF_CSRF_ENABLED", False)
        or not current_app.extensions.get("csrf", None)
        or g.get("csrf_valid", False)
    ):
        return None

    if cv("CSRF_PROTECT_MECHANISMS"):
        if method in cv("CSRF_PROTECT_MECHANISMS"):
            try:
                _csrf.protect()  # type: ignore
            except CSRFError as e:
                if json_response:
                    payload = json_error_response(errors=e.description)
                    return _security._render_json(payload, 400, None, None)
                raise
            return None
    set_request_attr("csrf_valid", True)  # flask_wtf global
    return None


def http_auth_required(realm: t.Any) -> DecoratedView:
    """Decorator that protects endpoints using Basic HTTP authentication.

    :param realm: optional realm name

    If authentication fails, then a 401 with the 'WWW-Authenticate' header set will be
    returned.

    Once authenticated, if so configured, CSRF protection will be tested.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if _check_http_auth():
                eresponse = handle_csrf("basic", _security._want_json(request))
                if eresponse:
                    return eresponse
                set_request_attr("fs_authn_via", "basic")
                return current_app.ensure_sync(fn)(*args, **kwargs)
            r = cv("DEFAULT_HTTP_AUTH_REALM") if callable(realm) else realm
            h = {"WWW-Authenticate": f'Basic realm="{r}"'}
            return _security._unauthn_handler(["basic"], headers=h)

        return wrapper

    if callable(realm):
        return decorator(realm)
    return decorator


def auth_token_required(fn: DecoratedView) -> DecoratedView:
    """Decorator that protects endpoints using token authentication. The token
    should be added to the request by the client by using a query string
    variable with a name equal to the configuration value of
    :py:data:`SECURITY_TOKEN_AUTHENTICATION_KEY` or in a request header named that of
    the configuration value of :py:data:`SECURITY_TOKEN_AUTHENTICATION_HEADER`

    Once authenticated, if so configured, CSRF protection will be tested.
    """

    @wraps(fn)
    def decorated(*args, **kwargs):
        if _check_token():
            eresponse = handle_csrf("token", _security._want_json(request))
            if eresponse:
                return eresponse
            set_request_attr("fs_authn_via", "token")
            return current_app.ensure_sync(fn)(*args, **kwargs)
        return _security._unauthn_handler(["token"])

    return t.cast(DecoratedView, decorated)


def auth_required(
    *auth_methods: str | t.Callable[[], list[str]] | None,
    within: int | float | t.Callable[[], datetime.timedelta] = -1,
    grace: int | float | t.Callable[[], datetime.timedelta] | None = None,
) -> DecoratedView:
    """
    Decorator that protects endpoints through multiple mechanisms.
    Example::

        @app.route('/dashboard')
        @auth_required('token', 'session')
        def dashboard():
            return 'Dashboard'

    :param auth_methods: Specified mechanisms (token, basic, session). If not specified
        then all current available mechanisms (except "basic") will be tried. A callable
        can also be passed (useful if you need app/request context). The callable
        must return a list.
    :param within: Add 'freshness' check to authentication. Is either an int
        specifying # of minutes, or a callable that returns a timedelta. For timedeltas,
        timedelta.total_seconds() is used for the calculations:

            - If > 0, then the caller must have authenticated within the time specified
              (as measured using the session cookie or authentication token).
            - If < 0 (the default) no freshness check is performed.

        Note that Basic Auth, by definition, is always 'fresh' and will never result in
        a redirect/error.
    :param grace: Add a grace period for freshness checks. As above, either an int
        or a callable returning a timedelta. If not specified then
        :py:data:`SECURITY_FRESHNESS_GRACE_PERIOD` is used. The grace period allows
        callers to complete the required operations w/o being prompted again.
        See :meth:`flask_security.check_and_update_authn_fresh` for details.

    Note that regardless of order specified - they will be tried in the following
    order: token, session, basic.

    The first mechanism that succeeds is used, following that, depending on
    configuration, CSRF protection will be tested.

    On authentication failure :meth:`.Security.unauthn_handler` will be called.

    As a side effect, upon successful authentication, the request global
     ``fs_authn_via`` will be set to the method ("basic", "token", "session")

    .. note::
        If "basic" is specified in addition to other methods, then if authentication
        fails, a 401 with the "WWW-Authenticate" header will be returned - rather than
        being redirected to the login view.

    .. versionchanged:: 3.3.0
       If ``auth_methods`` isn't specified, then all will be tried. Authentication
       mechanisms will always be tried in order of ``token``, ``session``, ``basic``
       regardless of how they are specified in the ``auth_methods`` parameter.

    .. versionchanged:: 3.4.0
        Added ``within`` and ``grace`` parameters to enforce a freshness check.

    .. versionchanged:: 3.4.4
        If ``auth_methods`` isn't specified try all mechanisms EXCEPT ``basic``.

    .. versionchanged:: 4.0.0
        auth_methods can be passed as a callable.

    """

    login_mechanisms = {
        "token": lambda: _check_token(),
        "session": lambda: _check_session(),
        "basic": lambda: _check_http_auth(),
    }
    mechanisms_order = ["token", "session", "basic"]

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(
            *args, auth_methods=auth_methods, within=within, grace=grace, **kwargs
        ):
            if callable(within):
                within = within()
            else:
                within = datetime.timedelta(minutes=within)
            if grace is None:
                grace = cv("FRESHNESS_GRACE_PERIOD")
            elif callable(grace):
                grace = grace()
            else:
                grace = datetime.timedelta(minutes=grace)

            if not auth_methods:
                ams = {"session", "token"}
            else:
                ams = []
                for am in auth_methods:
                    if callable(am):
                        ams.extend(am())
                    else:
                        ams.append(am)

            h = {}
            if "basic" in ams:
                r = cv("DEFAULT_HTTP_AUTH_REALM")
                h["WWW-Authenticate"] = f'Basic realm="{r}"'
            mechanisms = [
                (method, login_mechanisms.get(method))
                for method in mechanisms_order
                if method in ams
            ]
            for method, mechanism in mechanisms:
                if mechanism and mechanism():
                    # successfully authenticated. Basic auth is by definition 'fresh'.
                    # If 'within' is set - check for freshness of authentication.
                    if not check_and_update_authn_fresh(within, grace, method):
                        return _security._reauthn_handler(within, grace)
                    if eresponse := handle_csrf(method, _security._want_json(request)):
                        return eresponse
                    set_request_attr("fs_authn_via", method)
                    return current_app.ensure_sync(fn)(*args, **kwargs)
            return _security._unauthn_handler(ams, headers=h)

        return decorated_view

    return wrapper


def unauth_csrf(
    fall_through: bool = False,
) -> DecoratedView:
    """Decorator for endpoints that don't need authentication
    but do want CSRF checks (available via Header rather than just form).
    This is required when setting *WTF_CSRF_CHECK_DEFAULT* = **False** since in that
    case, without this decorator, the form validation will attempt to do the CSRF
    check, and that will fail since the csrf-token is in the header (for pure JSON
    requests).

    This decorator does nothing unless Flask-WTF::CSRFProtect has been initialized.

    This decorator does nothing if *WTF_CSRF_ENABLED* == **False**.

    This decorator does nothing if the caller is authenticated.

    This decorator will suppress CSRF if caller isn't authenticated and has set the
    :py:data:`SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS` config variable to **True**.

    .. versionadded:: 3.3.0

    .. versionchanged:: 5.4.3
        The fall_through parameter is now ignored.
        Add code to properly handle JSON errors.
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            if (
                not current_app.config.get("WTF_CSRF_ENABLED", False)
                or not current_app.extensions.get("csrf", None)
                or g.get("csrf_valid", False)
            ):
                return current_app.ensure_sync(fn)(*args, **kwargs)

            if cv("CSRF_IGNORE_UNAUTH_ENDPOINTS") and not is_user_authenticated(
                current_user
            ):
                set_request_attr("csrf_valid", True)
            else:
                try:
                    _csrf.protect()
                except CSRFError as e:
                    if _security._want_json(request):
                        payload = json_error_response(errors=e.description)
                        return _security._render_json(payload, 400, None, None)
                    raise

            return current_app.ensure_sync(fn)(*args, **kwargs)

        return decorated

    return wrapper


def roles_required(*roles: str) -> DecoratedView:
    """Decorator which specifies that a user must have all the specified roles.
    Example::

        @app.route('/dashboard')
        @roles_required('admin', 'editor')
        def dashboard():
            return 'Dashboard'

    The current user must have both the `admin` role and `editor` role in order
    to view the page.

    :param roles: The required roles.
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            perms = [Permission(RoleNeed(role)) for role in roles]
            for perm in perms:
                if not perm.can():
                    return _security._unauthz_handler(
                        roles_required.__name__, list(roles)
                    )
            return current_app.ensure_sync(fn)(*args, **kwargs)

        return decorated_view

    return wrapper


def roles_accepted(*roles: str) -> DecoratedView:
    """Decorator which specifies that a user must have at least one of the
    specified roles. Example::

        @app.route('/create_post')
        @roles_accepted('editor', 'author')
        def create_post():
            return 'Create Post'

    The current user must have either the `editor` role or `author` role in
    order to view the page.

    :param roles: The possible roles.
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            perm = Permission(*(RoleNeed(role) for role in roles))
            if perm.can():
                return current_app.ensure_sync(fn)(*args, **kwargs)
            return _security._unauthz_handler(roles_accepted.__name__, list(roles))

        return decorated_view

    return wrapper


def permissions_required(*fsperms: str) -> DecoratedView:
    """Decorator which specifies that a user must have all the specified permissions.
    Example::

        @app.route('/dashboard')
        @permissions_required('admin-write', 'editor-write')
        def dashboard():
            return 'Dashboard'

    The current user must have BOTH permissions (via the roles it has)
    to view the page.

    N.B. Don't confuse these permissions with flask-principle Permission()!

    :param fsperms: The required permissions.

    .. versionadded:: 3.3.0
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            perms = [Permission(FsPermNeed(fsperm)) for fsperm in fsperms]
            for perm in perms:
                if not perm.can():
                    return _security._unauthz_handler(
                        permissions_required.__name__, list(fsperms)
                    )

            return current_app.ensure_sync(fn)(*args, **kwargs)

        return decorated_view

    return wrapper


def permissions_accepted(*fsperms: str) -> DecoratedView:
    """Decorator which specifies that a user must have at least one of the
    specified permissions. Example::

        @app.route('/create_post')
        @permissions_accepted('editor-write', 'author-wrote')
        def create_post():
            return 'Create Post'

    The current user must have one of the permissions (via the roles it has)
    to view the page.

    N.B. Don't confuse these permissions with flask-principle Permission()!

    :param fsperms: The possible permissions.

    .. versionadded:: 3.3.0
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            perm = Permission(*(FsPermNeed(fsperm) for fsperm in fsperms))
            if perm.can():
                return current_app.ensure_sync(fn)(*args, **kwargs)
            return _security._unauthz_handler(
                permissions_accepted.__name__, list(fsperms)
            )

        return decorated_view

    return wrapper


def anonymous_user_required(f: DecoratedView) -> DecoratedView:
    """Decorator which requires that caller NOT be logged in.
    If a logged in user accesses an endpoint protected with this decorator
    they will be redirected to the :py:data:`SECURITY_POST_LOGIN_VIEW`.
    If the caller requests a JSON response, a 400 will be returned.

    .. versionchanged:: 3.3.0
        Support for JSON response was added.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        if is_user_authenticated(current_user):
            if _security._want_json(request):
                payload = json_error_response(
                    errors=get_message("ANONYMOUS_USER_REQUIRED")[0]
                )
                return _security._render_json(payload, 400, None, None)
            else:
                return redirect(get_url(cv("POST_LOGIN_VIEW")))
        return current_app.ensure_sync(f)(*args, **kwargs)

    return t.cast(DecoratedView, wrapper)
