# -*- coding: utf-8 -*-
"""
    flask_security.decorators
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security decorators module

    :copyright: (c) 2012-2019 by Matt Wright.
    :copyright: (c) 2019 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from collections import namedtuple
from functools import wraps

from flask import (
    Response,
    _app_ctx_stack,
    _request_ctx_stack,
    abort,
    current_app,
    g,
    redirect,
    request,
    url_for,
)
from flask_login import current_user, login_required  # noqa: F401
from flask_principal import Identity, Permission, RoleNeed, identity_changed
from flask_wtf.csrf import CSRFError
from werkzeug.local import LocalProxy
from werkzeug.routing import BuildError

from . import utils

# Convenient references
_security = LocalProxy(lambda: current_app.extensions["security"])

_csrf = LocalProxy(lambda: current_app.extensions["csrf"])


_default_unauthorized_html = """
    <h1>Unauthorized</h1>
    <p>The server could not verify that you are authorized to access the URL
    requested. You either supplied the wrong credentials (e.g. a bad password),
    or your browser doesn't understand how to supply the credentials required.
    </p>
    """

BasicAuth = namedtuple("BasicAuth", "username, password")


def _get_unauthorized_response(text=None, headers=None):
    text = text or _default_unauthorized_html
    headers = headers or {}
    return Response(text, 401, headers)


def _get_unauthorized_view():
    view = utils.config_value("UNAUTHORIZED_VIEW")
    if view:
        if callable(view):
            view = view()
        else:
            try:
                view = url_for(view)
            except BuildError:
                view = None
        utils.do_flash(*utils.get_message("UNAUTHORIZED"))
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
        _request_ctx_stack.top.user = user
        identity_changed.send(app, identity=Identity(user.id))
        return True

    return False


def _check_http_auth():
    auth = request.authorization or BasicAuth(username=None, password=None)
    if not auth.username:
        return False
    user = _security.datastore.get_user(auth.username)

    if user and user.verify_and_update_password(auth.password):
        _security.datastore.commit()
        app = current_app._get_current_object()
        _request_ctx_stack.top.user = user
        identity_changed.send(app, identity=Identity(user.id))
        return True

    return False


def _handle_csrf(method):
    """ If configuration wants CSRF checks on some authentication
    methods, do that here.
    """
    if (
        not current_app.config.get("WTF_CSRF_ENABLED", False)
        or not current_app.extensions.get("csrf", None)
        or g.get("csrf_valid", False)
    ):
        return

    if utils.config_value("CSRF_PROTECT_MECHANISMS"):
        if method in utils.config_value("CSRF_PROTECT_MECHANISMS"):
            _csrf.protect()
        else:
            ctx = _app_ctx_stack.top
            ctx.fs_ignore_csrf = True


def http_auth_required(realm):
    """Decorator that protects endpoints using Basic HTTP authentication.

    :param realm: optional realm name

    Once authenticated, if so configured, CSRF protection will be tested.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if _check_http_auth():
                _handle_csrf("basic")
                return fn(*args, **kwargs)
            if _security._unauthorized_callback:
                return _security._unauthorized_callback()
            else:
                r = _security.default_http_auth_realm if callable(realm) else realm
                h = {"WWW-Authenticate": 'Basic realm="%s"' % r}
                return _get_unauthorized_response(headers=h)

        return wrapper

    if callable(realm):
        return decorator(realm)
    return decorator


def auth_token_required(fn):
    """Decorator that protects endpoints using token authentication. The token
    should be added to the request by the client by using a query string
    variable with a name equal to the configuration value of
    `SECURITY_TOKEN_AUTHENTICATION_KEY` or in a request header named that of
    the configuration value of `SECURITY_TOKEN_AUTHENTICATION_HEADER`

    Once authenticated, if so configured, CSRF protection will be tested.
    """

    @wraps(fn)
    def decorated(*args, **kwargs):
        if _check_token():
            _handle_csrf("token")
            return fn(*args, **kwargs)
        if _security._unauthorized_callback:
            return _security._unauthorized_callback()
        else:
            return _get_unauthorized_response()

    return decorated


def auth_required(*auth_methods):
    """
    Decorator that protects endpoints through multiple mechanisms
    Example::

        @app.route('/dashboard')
        @auth_required('token', 'session')
        def dashboard():
            return 'Dashboard'

    :param auth_methods: Specified mechanisms (token, basic, session)

    Note that regardless of order specified - they will be tried in the following
    order: token, session, basic.

    The first mechanism that succeeds is used, following that, depending on
    configuration, CSRF protection will be tested.
    """
    login_mechanisms = {
        "token": lambda: _check_token(),
        "session": lambda: current_user.is_authenticated,
        "basic": lambda: _check_http_auth(),
    }
    mechanisms_order = ["token", "session", "basic"]

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            h = {}
            mechanisms = [
                (method, login_mechanisms.get(method))
                for method in mechanisms_order
                if method in auth_methods
            ]
            for method, mechanism in mechanisms:
                if mechanism and mechanism():
                    _handle_csrf(method)
                    return fn(*args, **kwargs)
                elif method == "basic":
                    r = _security.default_http_auth_realm
                    h["WWW-Authenticate"] = 'Basic realm="%s"' % r
            if _security._unauthorized_callback:
                return _security._unauthorized_callback()
            else:
                return _get_unauthorized_response(headers=h)

        return decorated_view

    return wrapper


def unauth_csrf(fall_through=False):
    """Decorator for endpoints that don't need authentication
    but do want CSRF checks (available via Header rather than just form).
    This is required when setting WTF_CSRF_CHECK_DEFAULT=False since in that
    case, without this decorator, the form validation will attempt to do the CSRF
    check, and that will fail since the csrf-token is in the header (for pure JSON
    requests).

    This decorator does nothing unless Flask-WTF::CSRFProtect has been initialized.

    This decorator does nothing if WTF_CSRF_ENABLED==False.

    This decorator will always require CSRF if the caller is authenticated.

    This decorator will suppress CSRF if caller isn't authenticated and has set the
    "CSRF_IGNORE_UNAUTH_ENDPOINTS" config variable.

    :param fall_through: if set to True, then if CSRF fails here - simply keep going.
        This is appropriate if underlying view is form based and once the form is
        instantiated, the csrf_token will be available.
        Note that this can mask some errors such as 'The CSRF session token is missing.'
        meaning that the caller didn't send a session cookie and instead the caller
        might get a 'The CSRF token is missing.' error.
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            if not current_app.config.get(
                "WTF_CSRF_ENABLED", False
            ) or not current_app.extensions.get("csrf", None):
                return fn(*args, **kwargs)

            if (
                utils.config_value("CSRF_IGNORE_UNAUTH_ENDPOINTS")
                and not current_user.is_authenticated
            ):
                ctx = _app_ctx_stack.top
                ctx.fs_ignore_csrf = True
            else:
                try:
                    _csrf.protect()
                except CSRFError:
                    if not fall_through:
                        raise

            return fn(*args, **kwargs)

        return decorated

    return wrapper


def roles_required(*roles):
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
                        return _security._unauthorized_callback()
                    else:
                        return _get_unauthorized_view()
            return fn(*args, **kwargs)

        return decorated_view

    return wrapper


def roles_accepted(*roles):
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
            perm = Permission(*[RoleNeed(role) for role in roles])
            if perm.can():
                return fn(*args, **kwargs)
            if _security._unauthorized_callback:
                return _security._unauthorized_callback()
            else:
                return _get_unauthorized_view()

        return decorated_view

    return wrapper


def permissions_required(*fsperms):
    """Decorator which specifies that a user must have all the specified permissions.
    Example::

        @app.route('/dashboard')
        @permissions_required('admin-write', 'editor-write')
        def dashboard():
            return 'Dashboard'

    The current user must have BOTH permissions (via the roles it has)
    to view the page.

    .. versionadded:: 3.3.0

    N.B. Don't confuse these permissions with flask-principle Permission()!

    :param fsperms: The required permissions.
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            perms = [Permission(utils.FsPermNeed(fsperm)) for fsperm in fsperms]
            for perm in perms:
                if not perm.can():
                    if _security._unauthorized_callback:
                        return _security._unauthorized_callback()
                    else:
                        return _get_unauthorized_view()
            return fn(*args, **kwargs)

        return decorated_view

    return wrapper


def permissions_accepted(*fsperms):
    """Decorator which specifies that a user must have at least one of the
    specified permissions. Example::

        @app.route('/create_post')
        @permissions_accepted('editor-write', 'author-wrote')
        def create_post():
            return 'Create Post'

    The current user must have one of the permissions (via the roles it has)
    to view the page.

    .. versionadded:: 3.3.0

    N.B. Don't confuse these permissions with flask-principle Permission()!

    :param fsperms: The possible permimssions.
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            perm = Permission(*[utils.FsPermNeed(fsperm) for fsperm in fsperms])
            if perm.can():
                return fn(*args, **kwargs)
            if _security._unauthorized_callback:
                return _security._unauthorized_callback()
            else:
                return _get_unauthorized_view()

        return decorated_view

    return wrapper


def anonymous_user_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(utils.get_url(_security.post_login_view))
        return f(*args, **kwargs)

    return wrapper
