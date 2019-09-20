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

from flask import Response, _request_ctx_stack, abort, current_app, g, redirect, request
from flask_login import current_user, login_required  # noqa: F401
from flask_principal import Identity, Permission, RoleNeed, identity_changed
from flask_wtf.csrf import CSRFError
from werkzeug.local import LocalProxy
from werkzeug.routing import BuildError

from . import utils

# Convenient references
_security = LocalProxy(lambda: current_app.extensions["security"])

_csrf = LocalProxy(lambda: current_app.extensions["csrf"])

BasicAuth = namedtuple("BasicAuth", "username, password")

# NOTE: this is here for backwards compatibility, it is deprecated and
# to be removed in 4.0
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
    """ Default callback for failures to authenticate

    If caller wants JSON - return 401
    Otherwise - assume caller is html and redirect if possible to a login view.
    We let Flask-Login handle this.

    """
    unauthn_message, _ = utils.get_message("UNAUTHENTICATED")

    if utils.config_value("BACKWARDS_COMPAT_UNAUTHN"):
        return _get_unauthenticated_response(headers=headers)
    if _security._want_json(request):
        # TODO can/should we response with a WWW-Authenticate Header in all cases?
        payload = utils.json_error_response(errors=unauthn_message)
        return _security._render_json(payload, 401, headers, None)
    return _security.login_manager.unauthorized()


def default_unauthz_handler(func, params):
    unauthz_message, unauthz_message_type = utils.get_message("UNAUTHORIZED")
    if _security._want_json(request):
        payload = utils.json_error_response(errors=unauthz_message)
        return _security._render_json(payload, 403, None, None)
    view = utils.config_value("UNAUTHORIZED_VIEW")
    if view:
        if callable(view):
            view = view()
        else:
            try:
                view = utils.get_url(view)
            except BuildError:
                view = None
        utils.do_flash(unauthz_message, unauthz_message_type)
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


def handle_csrf(method):
    """ Invoke CSRF protection based on authentication method.

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

    if utils.config_value("CSRF_PROTECT_MECHANISMS"):
        if method in utils.config_value("CSRF_PROTECT_MECHANISMS"):
            _csrf.protect()
        else:
            _request_ctx_stack.top.fs_ignore_csrf = True


def http_auth_required(realm):
    """Decorator that protects endpoints using Basic HTTP authentication.

    :param realm: optional realm name

    Once authenticated, if so configured, CSRF protection will be tested.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if _check_http_auth():
                handle_csrf("basic")
                return fn(*args, **kwargs)
            if _security._unauthorized_callback:
                return _security._unauthorized_callback()
            else:
                r = _security.default_http_auth_realm if callable(realm) else realm
                h = {"WWW-Authenticate": 'Basic realm="%s"' % r}
                return _security._unauthn_handler(["basic"], headers=h)

        return wrapper

    if callable(realm):
        return decorator(realm)
    return decorator


def auth_token_required(fn):
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
            return fn(*args, **kwargs)
        if _security._unauthorized_callback:
            return _security._unauthorized_callback()
        else:
            return _security._unauthn_handler(["token"])

    return decorated


def auth_required(*auth_methods):
    """
    Decorator that protects endpoints through multiple mechanisms
    Example::

        @app.route('/dashboard')
        @auth_required('token', 'session')
        def dashboard():
            return 'Dashboard'

    :param auth_methods: Specified mechanisms (token, basic, session). If not specified
        then all current available mechanisms will be tried.

    Note that regardless of order specified - they will be tried in the following
    order: token, session, basic.

    The first mechanism that succeeds is used, following that, depending on
    configuration, CSRF protection will be tested.

    .. versionchanged:: 3.3.0
       If ``auth_methods`` isn't specified, then all will be tried. Authentication
       mechanisms will always be tried in order of ``token``, ``session``, ``basic``
       regardless of how they are specified in the ``auth_methods`` parameter.
    """
    login_mechanisms = {
        "token": lambda: _check_token(),
        "session": lambda: current_user.is_authenticated,
        "basic": lambda: _check_http_auth(),
    }
    mechanisms_order = ["token", "session", "basic"]
    if not auth_methods:
        auth_methods = {"basic", "session", "token"}
    else:
        auth_methods = [am for am in auth_methods]

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
                    handle_csrf(method)
                    return fn(*args, **kwargs)
                elif method == "basic":
                    r = _security.default_http_auth_realm
                    h["WWW-Authenticate"] = 'Basic realm="%s"' % r
            if _security._unauthorized_callback:
                return _security._unauthorized_callback()
            else:
                return _security._unauthn_handler(auth_methods, headers=h)

        return decorated_view

    return wrapper


def unauth_csrf(fall_through=False):
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
                utils.config_value("CSRF_IGNORE_UNAUTH_ENDPOINTS")
                and not current_user.is_authenticated
            ):
                _request_ctx_stack.top.fs_ignore_csrf = True
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
                        # Backwards compat - deprecated
                        return _security._unauthorized_callback()
                    return _security._unauthz_handler(roles_required, list(roles))
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
                # Backwards compat - deprecated
                return _security._unauthorized_callback()
            return _security._unauthz_handler(roles_accepted, list(roles))

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

    N.B. Don't confuse these permissions with flask-principle Permission()!

    :param fsperms: The required permissions.

    .. versionadded:: 3.3.0
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            perms = [Permission(utils.FsPermNeed(fsperm)) for fsperm in fsperms]
            for perm in perms:
                if not perm.can():
                    if _security._unauthorized_callback:
                        # Backwards compat - deprecated
                        return _security._unauthorized_callback()
                    return _security._unauthz_handler(
                        permissions_required, list(fsperms)
                    )

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

    N.B. Don't confuse these permissions with flask-principle Permission()!

    :param fsperms: The possible permissions.

    .. versionadded:: 3.3.0
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            perm = Permission(*[utils.FsPermNeed(fsperm) for fsperm in fsperms])
            if perm.can():
                return fn(*args, **kwargs)
            if _security._unauthorized_callback:
                # Backwards compat - deprecated
                return _security._unauthorized_callback()
            return _security._unauthz_handler(permissions_accepted, list(fsperms))

        return decorated_view

    return wrapper


def anonymous_user_required(f):
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
                payload = utils.json_error_response(
                    errors=utils.get_message("ANONYMOUS_USER_REQUIRED")[0]
                )
                return _security._render_json(payload, 400, None, None)
            else:
                return redirect(utils.get_url(_security.post_login_view))
        return f(*args, **kwargs)

    return wrapper
