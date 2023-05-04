"""
    flask_security.decorators
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security decorators module

    :copyright: (c) 2012-2019 by Matt Wright.
    :copyright: (c) 2019-2023 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from collections import namedtuple
import datetime
from functools import wraps
import typing as t

from flask import Response, abort, current_app, g, redirect, request
from flask_login import current_user, login_required  # noqa: F401
from flask_principal import Identity, Permission, RoleNeed, identity_changed
from flask_wtf.csrf import CSRFError
from werkzeug.local import LocalProxy
from werkzeug.routing import BuildError

from .proxies import _security, DecoratedView
from .utils import (
    FsPermNeed,
    config_value,
    do_flash,
    get_message,
    get_url,
    lookup_identity,
    check_and_update_authn_fresh,
    json_error_response,
    set_request_attr,
    url_for_security,
)

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


def _get_unauthorized_response(text=None, headers=None):  # pragma: no cover
    # People called this - even though it isn't public - no harm in keeping it.
    return _get_unauthenticated_response(text, headers)


def default_unauthn_handler(mechanisms, headers=None):
    """Default callback for failures to authenticate

    If caller wants JSON - return 401.
    If caller wants BasicAuth - return 401 (the WWW-Authenticate header is set).
    Otherwise - assume caller is html and redirect if possible to a login view.
    We let Flask-Login handle this.

    """
    headers = headers or {}
    msg = get_message("UNAUTHENTICATED")[0]

    if config_value("BACKWARDS_COMPAT_UNAUTHN"):
        return _get_unauthenticated_response(headers=headers)
    if _security._want_json(request):
        payload = json_error_response(errors=msg)
        return _security._render_json(payload, 401, headers, None)

    # Basic-Auth is often used to provide a browser based login form and then the
    # browser will always add the BasicAuth credentials. For that to work we need to
    # return 401 and not redirect to our login view.
    if "WWW-Authenticate" in headers:
        return Response(msg, 401, headers)
    return _security.login_manager.unauthorized()


def default_reauthn_handler(within, grace):
    """Default callback for 'freshness' related authn failures.

    If caller wants JSON - return 401
    Otherwise - assume caller is html and redirect if possible to configured view.

    """
    m, c = get_message("REAUTHENTICATION_REQUIRED")

    if _security._want_json(request):
        from .webauthn import has_webauthn

        is_us = config_value("UNIFIED_SIGNIN")
        payload = json_error_response(errors=m)
        payload["reauth_required"] = True
        payload["unified_signin_enabled"] = is_us
        payload["has_webauthn_verify_credential"] = has_webauthn(
            current_user, config_value("WAN_ALLOW_AS_VERIFY")
        )
        return _security._render_json(payload, 401, None, None)

    view = "us_verify" if config_value("UNIFIED_SIGNIN") else "verify"
    do_flash(m, c)
    redirect_url = url_for_security(view, next=request.url)
    return redirect(redirect_url)


def default_unauthz_handler(func_name, params):
    unauthz_message, unauthz_message_type = get_message("UNAUTHORIZED")
    if _security._want_json(request):
        payload = json_error_response(errors=unauthz_message)
        return _security._render_json(payload, 403, None, None)
    view = config_value("UNAUTHORIZED_VIEW")
    if view:
        if callable(view):
            view = view()
        else:
            try:
                view = get_url(view)
            except BuildError:
                view = None
        do_flash(unauthz_message, unauthz_message_type)
        redirect_to = "/"
        if request.referrer and not request.referrer.split("?")[0].endswith(
            request.path
        ):
            redirect_to = request.referrer

        return redirect(view or redirect_to)
    abort(403)


def _check_token():
    user = _security.login_manager.request_callback(request)
    if user and user.is_authenticated:
        app = current_app._get_current_object()
        identity_changed.send(app, identity=Identity(user.fs_uniquifier))
        return True

    return False


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
        app = current_app._get_current_object()
        identity_changed.send(app, identity=Identity(user.fs_uniquifier))
        return True

    return False


def handle_csrf(method: t.Optional[str]) -> None:
    """Invoke CSRF protection based on authentication method.

    Usually this is called as part of a decorator, but if that isn't
    appropriate, endpoint code can call this directly.

    If CSRF protection is appropriate, this will call flask_wtf::protect() which
    will raise a ValidationError on CSRF failure.

    This routine does nothing if any of these are true:

        #) *WTF_CSRF_ENABLED* is set to False

        #) the Flask-WTF CSRF module hasn't been initialized

        #) csrfProtect already checked and accepted the token

    If the passed in method is not in *SECURITY_CSRF_PROTECT_MECHANISMS* then not only
    will no CSRF code be run, but a flag in the current context ``fs_ignore_csrf``
    will be set so that downstream code knows to ignore any CSRF checks.

    .. versionadded:: 3.3.0
    """
    if (
        not current_app.config.get("WTF_CSRF_ENABLED", False)
        or not current_app.extensions.get("csrf", None)
        or g.get("csrf_valid", False)
    ):
        return

    if config_value("CSRF_PROTECT_MECHANISMS"):
        if method in config_value("CSRF_PROTECT_MECHANISMS"):
            _csrf.protect()  # type: ignore
        else:
            set_request_attr("fs_ignore_csrf", True)


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
                handle_csrf("basic")
                set_request_attr("fs_authn_via", "basic")
                return fn(*args, **kwargs)
            if _security._unauthorized_callback:
                return _security._unauthorized_callback()
            else:
                r = _security.default_http_auth_realm if callable(realm) else realm
                h = {"WWW-Authenticate": f'Basic realm="{r}"'}
                return _security._unauthn_handler(["basic"], h)

        return wrapper

    if callable(realm):
        return decorator(realm)
    return decorator


def auth_token_required(fn: DecoratedView) -> DecoratedView:
    """Decorator that protects endpoints using token authentication. The token
    should be added to the request by the client by using a query string
    variable with a name equal to the configuration value of
    *SECURITY_TOKEN_AUTHENTICATION_KEY* or in a request header named that of
    the configuration value of *SECURITY_TOKEN_AUTHENTICATION_HEADER*

    Once authenticated, if so configured, CSRF protection will be tested.
    """

    @wraps(fn)
    def decorated(*args, **kwargs):
        if _check_token():
            handle_csrf("token")
            set_request_attr("fs_authn_via", "token")
            return fn(*args, **kwargs)
        if _security._unauthorized_callback:
            return _security._unauthorized_callback()
        else:
            return _security._unauthn_handler(["token"])

    return t.cast(DecoratedView, decorated)


def auth_required(
    *auth_methods: t.Union[str, t.Callable[[], t.List[str]], None],
    within: t.Union[int, float, t.Callable[[], datetime.timedelta]] = -1,
    grace: t.Optional[t.Union[int, float, t.Callable[[], datetime.timedelta]]] = None,
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
              (as measured using the session cookie).
            - If 0 and not within the grace period (see below) the caller will
              always be redirected to re-authenticate.
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

    On authentication failure `.Security.unauthorized_callback` (deprecated)
    or :meth:`.Security.unauthn_handler` will be called.

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
        "session": lambda: current_user.is_authenticated,
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
                grace = config_value("FRESHNESS_GRACE_PERIOD")
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
                r = _security.default_http_auth_realm
                h["WWW-Authenticate"] = f'Basic realm="{r}"'
            mechanisms = [
                (method, login_mechanisms.get(method))
                for method in mechanisms_order
                if method in ams
            ]
            for method, mechanism in mechanisms:
                if mechanism and mechanism():
                    # successfully authenticated. Basic auth is by definition 'fresh'.
                    # Note that using token auth is ok - but caller still has to pass
                    # in a session cookie...
                    if not check_and_update_authn_fresh(within, grace, method):
                        return _security._reauthn_handler(within, grace)
                    handle_csrf(method)
                    set_request_attr("fs_authn_via", method)
                    return fn(*args, **kwargs)
            if _security._unauthorized_callback:
                return _security._unauthorized_callback()
            else:
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

    This decorator will always require CSRF if the caller is authenticated.

    This decorator will suppress CSRF if caller isn't authenticated and has set the
    *SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS* config variable.

    :param fall_through: if set to True, then if CSRF fails here - simply keep going.
        This is appropriate if underlying view is form based and once the form is
        instantiated, the csrf_token will be available.
        Note that this can mask some errors such as 'The CSRF session token is missing.'
        meaning that the caller didn't send a session cookie and instead the caller
        might get a 'The CSRF token is missing.' error.

    .. versionadded:: 3.3.0
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            if not current_app.config.get(
                "WTF_CSRF_ENABLED", False
            ) or not current_app.extensions.get("csrf", None):
                return fn(*args, **kwargs)

            if (
                config_value("CSRF_IGNORE_UNAUTH_ENDPOINTS")
                and not current_user.is_authenticated
            ):
                set_request_attr("fs_ignore_csrf", True)
            else:
                try:
                    _csrf.protect()
                except CSRFError:
                    if not fall_through:
                        raise

            return fn(*args, **kwargs)

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
                    if _security._unauthorized_callback:
                        # Backwards compat - deprecated
                        return _security._unauthorized_callback()
                    return _security._unauthz_handler(
                        roles_required.__name__, list(roles)
                    )
            return fn(*args, **kwargs)

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
                return fn(*args, **kwargs)
            if _security._unauthorized_callback:
                # Backwards compat - deprecated
                return _security._unauthorized_callback()
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
                    if _security._unauthorized_callback:
                        # Backwards compat - deprecated
                        return _security._unauthorized_callback()
                    return _security._unauthz_handler(
                        permissions_required.__name__, list(fsperms)
                    )

            return fn(*args, **kwargs)

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
                return fn(*args, **kwargs)
            if _security._unauthorized_callback:
                # Backwards compat - deprecated
                return _security._unauthorized_callback()
            return _security._unauthz_handler(
                permissions_accepted.__name__, list(fsperms)
            )

        return decorated_view

    return wrapper


def anonymous_user_required(f: DecoratedView) -> DecoratedView:
    """Decorator which requires that caller NOT be logged in.
    If a logged in user accesses an endpoint protected with this decorator
    they will be redirected to the *SECURITY_POST_LOGIN_VIEW*.
    If the caller requests a JSON response, a 400 will be returned.

    .. versionchanged:: 3.3.0
        Support for JSON response was added.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            if _security._want_json(request):
                payload = json_error_response(
                    errors=get_message("ANONYMOUS_USER_REQUIRED")[0]
                )
                return _security._render_json(payload, 400, None, None)
            else:
                return redirect(get_url(_security.post_login_view))
        return f(*args, **kwargs)

    return t.cast(DecoratedView, wrapper)
