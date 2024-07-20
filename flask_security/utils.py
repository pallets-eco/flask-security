"""
    flask_security.utils
    ~~~~~~~~~~~~~~~~~~~~

    Flask-Security utils module

    :copyright: (c) 2012-2019 by Matt Wright.
    :copyright: (c) 2019-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from __future__ import annotations

import abc
import base64
from datetime import datetime, timedelta, timezone
from functools import partial
import hashlib
import hmac
import time
import typing as t
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit, urlencode
import urllib.request
import urllib.error
import warnings

from flask import (
    Response,
    after_this_request,
    current_app,
    flash,
    g,
    redirect,
    request,
    render_template,
    session,
    url_for,
)
from flask_login import login_user as _login_user
from flask_login import logout_user as _logout_user
from flask_login import current_user
from flask_login import COOKIE_NAME as REMEMBER_COOKIE_NAME
from flask_principal import AnonymousIdentity, Identity, identity_changed, Need
from flask_wtf import csrf, FlaskForm
from wtforms import ValidationError
from itsdangerous import BadSignature, SignatureExpired
from werkzeug.local import LocalProxy
from werkzeug.datastructures import MultiDict

from .quart_compat import best, get_quart_status
from .proxies import _security, _datastore, _pwd_context, _hashing_context
from .signals import user_authenticated

if t.TYPE_CHECKING:  # pragma: no cover
    from flask import Flask
    from flask.typing import ResponseValue
    from flask_security import UserMixin

localize_callback = LocalProxy(lambda: _security.i18n_domain.gettext)

FsPermNeed = partial(Need, "fsperm")
FsPermNeed.__doc__ = """A need with the method preset to `"fsperm"`."""


def _(translate):
    """Identity function to mark strings for translation."""
    return translate


def get_request_attr(name: str) -> t.Any:
    """Retrieve a request local attribute.

    Current public attributes are:

    **fs_authn_via**
        will be set to the authentication mechanism (session, token, basic)
        that the current request was authenticated with.

    Returns None if attribute doesn't exist.

    .. versionadded:: 4.0.0
    .. versionchanged:: 4.1.5
        Use 'g' rather than request_ctx stack which is going away post Flask 2.2
    """
    return getattr(g, name, None)


def set_request_attr(name, value):
    return setattr(g, name, value)


"""
Most view functions that modify the DB will call ``after_this_request(view_commit)``
Quart compatibility needs an async version
"""
if get_quart_status():  # pragma: no cover

    async def view_commit(response=None):
        _datastore.commit()
        return response

else:

    def view_commit(response=None):
        _datastore.commit()
        return response


# From a miguel grinberg blog around dealing with 3.12.
# Our default SQLAlchemy Datetime is naive.
# Note that most code should call _security.datetime_factory()
def aware_utcnow():
    return datetime.now(timezone.utc)


def aware_utcfromtimestamp(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc)


def naive_utcnow():
    return aware_utcnow().replace(tzinfo=None)


def naive_utcfromtimestamp(timestamp):
    return aware_utcfromtimestamp(timestamp).replace(tzinfo=None)


def find_csrf_field_name():
    """
    We need to clear it on logout (since that isn't being done by Flask-WTF).
    The field name is configurable withing Flask-WTF as well as being
    overridable.
    We take the field name from the login_form as set by the configuration.
    """
    from .forms import DummyForm

    form = DummyForm(formdata=None)
    if hasattr(form.meta, "csrf_field_name"):
        return form.meta.csrf_field_name
    return None


def is_user_authenticated(user: UserMixin | None) -> bool:
    """
    return True if user is authenticated.

    With Flask-Login <=0.6.x and Flask-Security <5.4 current_user was always
    set - for non-authenticated users it pointed to an AnonymousUser
    Flask-Login is experimenting (11/5/23) with a LOGIN_NO_ANONYMOUS which will set
    current_user to None and deprecate is_authenticated (current_user non None implies
    authenticated).
    We have a configuration variable ANONYMOUS_USER_DISABLED which if true will force
    current_user to None on unauthenticated as well
    """
    if config_value("ANONYMOUS_USER_DISABLED"):
        # Note that user often is current_user which is a proxy and isn't ever actually
        # 'None'
        return bool(user)
    return bool(user and user.is_authenticated)


def login_user(
    user: UserMixin,
    remember: bool | None = None,
    authn_via: list[str] | None = None,
) -> bool:
    """Perform the login routine.

    If :py:data:`SECURITY_TRACKABLE` is used, make sure you commit changes after this
    request (i.e. ``app.security.datastore.commit()``).

    :param user: The user to login
    :param remember: Flag specifying if the remember cookie should be set.
                     If ``None`` use value of :py:data:`SECURITY_DEFAULT_REMEMBER_ME`
    :param authn_via: A list of strings denoting which mechanism(s) the user
        authenticated with.
        These should be one or more of ["password", "sms", "authenticator", "email"] or
        other 'auto-login' mechanisms.
    :return: True if user successfully logged in.
    """

    if remember is None:
        remember = config_value("DEFAULT_REMEMBER_ME")

    if not _login_user(user, remember):  # pragma: no cover
        return False

    if _security.trackable:
        remote_addr = request.remote_addr or None  # make sure it is None

        old_current_login, new_current_login = (
            user.current_login_at,
            _security.datetime_factory(),
        )
        old_current_ip, new_current_ip = user.current_login_ip, remote_addr

        user.last_login_at = old_current_login or new_current_login
        user.current_login_at = new_current_login
        user.last_login_ip = old_current_ip
        user.current_login_ip = new_current_ip
        user.login_count = user.login_count + 1 if user.login_count else 1

        _datastore.put(user)

    session["fs_cc"] = "set"  # CSRF cookie
    session["fs_paa"] = time.time()  # Primary authentication at - timestamp

    identity_changed.send(
        current_app._get_current_object(),  # type: ignore[attr-defined]
        _async_wrapper=current_app.ensure_sync,  # type: ignore[arg-type]
        identity=Identity(user.fs_uniquifier),
    )

    user_authenticated.send(
        current_app._get_current_object(),  # type: ignore[attr-defined]
        _async_wrapper=current_app.ensure_sync,  # type: ignore[arg-type]
        user=user,
        authn_via=authn_via,
    )
    return True


def logout_user() -> None:
    """Logs out the current user.

    This will also clean up the remember me cookie if it exists.

    This sends an ``identity_changed`` signal to note that the current
    identity is now the `AnonymousIdentity`
    """

    for key in (
        "identity.name",
        "identity.auth_type",
        "fs_paa",
        "fs_gexp",
        "fs_oauth_next",
    ):
        session.pop(key, None)

    # Clear csrf token between sessions.
    # Ideally this would be handled by Flask-WTF but...
    # We don't clear entire session since Flask-Login seems to like having it.
    csrf_field_name = find_csrf_field_name()
    if csrf_field_name:
        session.pop(csrf_field_name, None)
        # Flask-WTF 'caches' csrf_token - and only set the session if not already
        # in 'g'. Be sure to clear both. This affects at least /confirm
        g.pop(csrf_field_name, None)
    session["fs_cc"] = "clear"
    identity_changed.send(
        current_app._get_current_object(),  # type: ignore
        _async_wrapper=current_app.ensure_sync,
        identity=AnonymousIdentity(),
    )
    _logout_user()


def check_and_update_authn_fresh(
    within: timedelta,
    grace: timedelta,
    method: str | None = None,
) -> bool:
    """Check if user authenticated within specified time and update grace period.

    :param within: A timedelta specifying the maximum time in the past that the caller
                  authenticated that is still considered 'fresh'.
    :param grace: A timedelta that, if the current session is considered 'fresh'
                  will set a grace period for which freshness won't be checked.
                  The intent here is that the caller shouldn't get part-way though
                  a set of operations and suddenly be required to authenticate again.
                  This is not supported for authentication tokens.
    :param method: Optional - if set and == "basic" then will always return True.
                  (since basic-auth sends username/password on every request)

    If within.total_seconds() is negative, will always return True (always 'fresh').
    This effectively just disables this entire mechanism.

    within.total_seconds() == 0 results in undefined behavior.

    If "fs_gexp" is in the session and the current timestamp is less than that,
    return True and extend grace time (i.e. set fs_gexp to current time + grace).

    Be aware that for this to work, state is required to be sent from the client.
    Flask security adds this state to the session (cookie) and the auth token.
    Without this state, 'False' is always returned - (not fresh).

    .. warning::
        Be sure the caller is already authenticated PRIOR to calling this method.

    .. versionadded:: 3.4.0

    .. versionchanged:: 4.0.0
        Added `method` parameter.

    .. versionchanged:: 5.5.0
        Grab 'Primary Authenticated At' from  request_attrs
        which is set from either session or auth token
    """

    if method == "basic":
        return True

    if within.total_seconds() < 0:
        # this means 'always fresh'
        return True

    if not (paa := get_request_attr("fs_paa")):
        # No recorded primary authenticated at time, you can't play.
        return False

    now = naive_utcnow()
    new_exp = now + grace
    grace_ts = int(new_exp.timestamp())

    if fs_gexp := session.get("fs_gexp", None):
        if now.timestamp() < fs_gexp:
            # Within grace period - extend it, and we're good.
            session["fs_gexp"] = grace_ts
            return True

    authn_time = naive_utcfromtimestamp(paa)
    # allow for some time drift where it's possible authn_time is in the future
    # but let's be cautious and not allow arbitrary future times
    delta = now - authn_time
    if within > delta > -within:
        session["fs_gexp"] = grace_ts
        return True
    return False


def get_hmac(password: str | bytes) -> bytes:
    """Returns a Base64 encoded HMAC+SHA512 of the password signed with
    the salt specified by :py:data:`SECURITY_PASSWORD_SALT`.

    :param password: The password to sign
    """
    if not (salt := config_value("PASSWORD_SALT")):
        raise RuntimeError(
            "The configuration value `SECURITY_PASSWORD_SALT` must "
            "not be None when the value of `SECURITY_PASSWORD_HASH` is "
            'set to "%s"' % config_value("PASSWORD_HASH")
        )

    h = hmac.new(encode_string(salt), encode_string(password), hashlib.sha512)
    return base64.b64encode(h.digest())


def verify_password(password: str | bytes, password_hash: str | bytes) -> bool:
    """Returns ``True`` if the password matches the supplied hash.

    :param password: A plaintext password to verify
    :param password_hash: The expected hash value of the password
                          (usually from your database)

    .. note::
        Make sure that the password passed in has already been normalized.
    """
    if use_double_hash(password_hash):
        password = get_hmac(password)

    return _pwd_context.verify(password, password_hash)


def verify_and_update_password(password: str | bytes, user: UserMixin) -> bool:
    """Returns ``True`` if the password is valid for the specified user.

    Additionally, the hashed password in the database is updated if the
    hashing algorithm happens to have changed.

    N.B. you MUST call DB commit if you are using a session-based datastore
    (such as SqlAlchemy) since the user instance might have been altered
    (i.e. ``app.security.datastore.commit()``).
    This is usually handled in the view.

    :param password: A plaintext password to verify
    :param user: The user to verify against

    .. tip::
        This should not be called directly - rather use
        :meth:`.UserMixin.verify_and_update_password`

    """
    if use_double_hash(user.password):
        verified = _pwd_context.verify(get_hmac(password), user.password)
    else:
        # Try with original password.
        verified = _pwd_context.verify(password, user.password)

    if verified and (user.password is None or _pwd_context.needs_update(user.password)):
        user.password = hash_password(password)
        _datastore.put(user)
    return verified


def hash_password(password: str | bytes) -> str:
    """Hash the specified plaintext password.

    Unless the hash algorithm (as specified by
    :py:data:`SECURITY_PASSWORD_HASH`) is listed in
    the configuration variable :py:data:`SECURITY_PASSWORD_SINGLE_HASH`,
    perform a double hash - first create an HMAC from the plaintext password
    and the value of :py:data:`SECURITY_PASSWORD_SALT`,
    then use the configured hashing algorithm.
    This satisfies OWASP/ASVS section 2.4.5: 'provide additional
    iteration of a key derivation'.

    .. versionadded:: 2.0.2

    :param password: The plaintext password to hash
    """
    if use_double_hash():
        password = get_hmac(password).decode("ascii")

    # Passing in options as part of hash is deprecated in passlib 1.7
    # and new algorithms like argon2 don't even support it.
    return _pwd_context.hash(
        password,
        **config_value("PASSWORD_HASH_OPTIONS", default={}).get(
            config_value("PASSWORD_HASH"), {}
        ),
    )


def encode_string(string):
    """Encodes a string to bytes, if it isn't already.

    :param string: The string to encode"""

    if isinstance(string, str):
        string = string.encode("utf-8")
    return string


def hash_data(data):
    return _hashing_context.hash(encode_string(data))


def verify_hash(hashed_data, compare_data):
    return _hashing_context.verify(encode_string(compare_data), hashed_data)


def suppress_form_csrf():
    """
    Return meta contents if we should suppress form from attempting to validate CSRF.

    If app doesn't want CSRF for unauth endpoints then check if caller is authenticated
    or not (many endpoints can be called either way).
    """
    if config_value("CSRF_IGNORE_UNAUTH_ENDPOINTS") and not is_user_authenticated(
        current_user
    ):
        return {"csrf": False}
    return {}


def do_flash(message: str, category: str) -> None:
    """Flash a message depending on if the `FLASH_MESSAGES` configuration
    value is set.

    :param message: The flash message
    :param category: The flash message category
    """
    if config_value("FLASH_MESSAGES"):
        flash(message, category)


def parse_auth_token(auth_token: str) -> dict[str, t.Any]:
    """Parse an authentication token.
    This will raise an exception if not properly signed or expired
    """
    tdata = dict()

    # This can raise BadSignature or SignatureExpired exceptions from itsdangerous
    raw_data = _security.remember_token_serializer.loads(
        auth_token, max_age=config_value("TOKEN_MAX_AGE")
    )

    # Version 3.x generated tokens that map to data with 3 elements,
    # and fs_uniquifier was on last element.
    # Version 4.0.0 generates tokens that map to data with only 1 element,
    # which maps to fs_uniquifier.
    # Version 5 and up are already a dict (with a version #)
    if isinstance(raw_data, dict):
        # new format - starting at ver=5
        if not all(k in raw_data for k in ["ver", "uid", "exp"]):
            raise ValueError("Token missing keys")
        tdata = raw_data
        if ts := tdata.get("exp"):
            if ts < int(time.time()):
                raise SignatureExpired("token[exp] value expired")
    else:
        # old tokens that were lists
        if len(raw_data) == 1:
            # version 4
            tdata["ver"] = "4"
            tdata["uid"] = raw_data[0]
        else:
            # version 3
            tdata["ver"] = "3"
            tdata["uid"] = raw_data[2]

    return tdata


def get_url(endpoint_or_url: str, qparams: dict[str, str] | None = None) -> str:
    """Returns a URL if a valid endpoint is found. Otherwise, returns the
    provided value.

    .. warning::
        If an endpoint ISN'T provided, then it is assumed that the URL
        is external to Flask and if the spa configuration REDIRECT_HOST
        is set will redirect to that host. This could be an issue in
        development.

    :param endpoint_or_url: The endpoint name or URL to default to
    :param qparams: additional query params to add to end of url
    :return: URL
    """
    try:
        return transform_url(url_for(endpoint_or_url), qparams)
    except Exception:
        # This is an external URL (no endpoint defined in app)
        # For (mostly) testing - allow changing/adding the url - for example
        # add a different host:port for cases where the UI is running
        # separately.
        if config_value("REDIRECT_HOST"):
            url = transform_url(
                endpoint_or_url, qparams, netloc=config_value("REDIRECT_HOST")
            )
        else:
            url = transform_url(endpoint_or_url, qparams)

        return url


def slash_url_suffix(url, suffix):
    """Adds a slash either to the beginning or the end of a suffix
    (which is to be appended to a URL), depending on whether or not
    the URL ends with a slash."""
    return url.endswith("/") and f"{suffix}/" or f"/{suffix}"


def transform_url(
    url: str, qparams: dict[str, str] | None = None, **kwargs: str
) -> str:
    """Modify url

    :param url: url to transform (can be relative)
    :param qparams: additional query params to add to end of url
    :param kwargs: pieces of URL to modify - e.g. netloc=localhost:8000
    :return: Modified URL

    .. versionadded:: 3.2.0
    """
    link_parse = urlsplit(url)
    if qparams:
        current_query = dict(parse_qsl(link_parse.query))
        current_query.update(qparams)
        link_parse = link_parse._replace(query=urlencode(current_query))
    return urlunsplit(link_parse._replace(**kwargs))


def get_security_endpoint_name(endpoint):
    return f"{config_value('BLUEPRINT_NAME')}.{endpoint}"


def url_for_security(endpoint: str, **values: t.Any) -> str:
    """Return a URL for the security blueprint

    :param endpoint: the endpoint of the URL (name of the function)
    :param values: the variable arguments of the URL rule
    :param _external: if set to `True`, an absolute URL is generated. Server
      address can be changed via `SERVER_NAME` configuration variable which
      defaults to `localhost`.
    :param _anchor: if provided this is added as anchor to the URL.
    :param _method: if provided this explicitly specifies an HTTP method.
    """
    endpoint = get_security_endpoint_name(endpoint)
    # mypy is complaining about this - but I think it's wrong?
    return url_for(endpoint, **values)  # type: ignore


def validate_redirect_url(url: str) -> bool:
    """Validate redirect URL
    In the default configuration only redirects to the same domain (and scheme)
    are allowed.
    The REDIRECT_ALLOW_SUBDOMAINS allows ANY subdomain of SERVER_NAME
     to be a redirect target.
    The REDIRECT_BASE_DOMAIN and REDIRECT_ALLOWED_SUBDOMAINS allow specifying 'side'
    redirects.
    """

    if url is None or url.strip() == "":
        return False
    url_next = urlsplit(url)
    url_base = urlsplit(request.host_url)
    if (url_next.netloc or url_next.scheme) and url_next.netloc != url_base.netloc:
        base_domain = current_app.config.get("SERVER_NAME")
        if (
            config_value("REDIRECT_ALLOW_SUBDOMAINS")
            and base_domain
            and (
                url_next.netloc == base_domain
                or url_next.netloc.endswith(f".{base_domain}")
            )
        ):
            return True
        base_domain = config_value("REDIRECT_BASE_DOMAIN")
        if base_domain:
            allowable = [
                f"{sub}.{base_domain}"
                for sub in config_value("REDIRECT_ALLOWED_SUBDOMAINS")
            ]
            return url_next.netloc in allowable
        return False
    return True


def get_post_action_redirect(
    config_key: str, next_loc: FlaskForm | MultiDict | dict | None
) -> str:
    """
    There is a security angle here - the result of this method is
    sent to Flask::redirect() - and we need to be sure that it can't be
    interpreted as a user-input external URL - that would mean we would
    have an 'open-redirect' vulnerability.

    Allowing an absolute redirect is a security issue - a so-called open-redirect.

    The complexity here is that urlsplit() does pretty well, but browsers even today
    May 2021 are very lenient in what they accept as URLs - for example:
        next=\\\\github.com
        next=%5C%5C%5Cgithub.com
        next=/////github.com
        next=%20\\\\github.com
        next=%20///github.com
        next=%20//github.com
        next=%19////github.com - i.e. browser will strip control chars
        next=%E2%80%8A///github.com - doesn't redirect! That is a unicode thin space.

    All will result in a null netloc and scheme from urlsplit - however many browsers
    will gladly strip off uninteresting characters and convert backslashes to forward
    slashes - and the cases above will actually cause a redirect to github.com
    Sigh.

    Some articles claim that a relative url has to start with a '/' - but that isn't
    strictly true. From: https://datatracker.ietf.org/doc/html/rfc3986#section-5
    a relative path can start with a "//", "/", a non-colon, or be empty. So it seems
    that all the above URLs are valid.
    By the time we get the URL, it has been unencoded - so we can't really determine
    if it is 'valid' since it appears that '/'s can appear in the URL if escaped.

    The solution is to simply 'quote' the path.
    """
    rurl = propagate_next(find_redirect(config_key), next_loc)
    (scheme, netloc, path, query, fragment) = urlsplit(rurl)
    safe_url = urlunsplit((scheme, netloc, quote(path), query, fragment))
    return safe_url


def get_post_login_redirect() -> str:
    return get_post_action_redirect("SECURITY_POST_LOGIN_VIEW", request.form)


def get_post_register_redirect() -> str:
    return get_post_action_redirect("SECURITY_POST_REGISTER_VIEW", request.form)


def get_post_logout_redirect() -> str:
    return get_post_action_redirect("SECURITY_POST_LOGOUT_VIEW", request.form)


def get_post_verify_redirect() -> str:
    return get_post_action_redirect("SECURITY_POST_VERIFY_VIEW", request.form)


def find_redirect(key: str) -> str:
    """Returns the URL to redirect to.

    :param key: The  application configuration key to search for
    """
    app_url = None
    if app_value := current_app.config[key.upper()]:
        app_url = get_url(app_value)
    rv = app_url or str(current_app.config.get("APPLICATION_ROOT", "/"))
    return rv


def propagate_next(fallback_url: str, form: FlaskForm | MultiDict | dict | None) -> str:
    """Compute appropriate redirect URL
    The application can add a 'next' query parameter or have 'next' as a form field.
    If either exist, make sure they are valid (not pointing to external location)
    If neither, return the fallback_url

    Can be passed either request.form
     (which is really a MultiDict OR a real form OR a dict with a 'next' key).
    """
    form_next = None
    if form and isinstance(form, FlaskForm):
        if hasattr(form, "next") and form.next.data:
            form_next = form.next.data
    elif form and form.get("next", None):
        form_next = str(form.get("next"))
    arg_next = request.args.get("next")

    urls = [
        get_url(form_next) if form_next else None,
        get_url(arg_next) if arg_next else None,
        fallback_url,
    ]
    for url in urls:
        if url and validate_redirect_url(url):
            return url
    raise ValueError("No valid redirect URL found - configuration error")


def simplify_url(base_url: str, redirect_url: str) -> str:
    """
    Reduces the scheme and host from the redirect_url so it can be passed
    as a relative URL in a query (e.g. next) param.
    For this method we aren't worrying about a valid url (e.g. if it points
    externally) - that will be handled by later requests.

    :param base_url: The URL to simplify 'against'.
    :param redirect_url: The URL to reduce.
    """
    b_url = urlsplit(base_url)
    r_url = urlsplit(redirect_url)

    if (not r_url.scheme or r_url.scheme == b_url.scheme) and (
        not r_url.netloc or r_url.netloc == b_url.netloc
    ):
        return urlunsplit(("", "", r_url.path, r_url.query, r_url.fragment))
    return redirect_url


def get_message(key: str, **kwargs: t.Any) -> tuple[str, str]:
    rv = config_value("MSG_" + key)
    return localize_callback(rv[0], **kwargs), rv[1]


def config_value(key, app=None, default=None, strict=True):
    """Get a Flask-Security configuration value.

    :param key: The configuration key without the prefix `SECURITY_`
    :param app: An optional specific application to inspect. Defaults to
                Flask's `current_app`
    :param default: An optional default value if the value is not set
    :param strict: if True, will raise ValueError if key doesn't exist
    """
    app = app or current_app
    key = f"SECURITY_{key.upper()}"
    # protect against spelling mistakes
    if strict and key not in app.config:
        raise ValueError(f"Key {key} doesn't exist")
    return app.config.get(key, default)


def get_max_age(key, app=None):
    td = get_within_delta(key + "_WITHIN", app)
    return td.seconds + td.days * 24 * 3600


def get_within_delta(key, app=None):
    """Get a timedelta object from the application configuration following
    the internal convention of::

        <Amount of Units> <Type of Units>

    Examples of valid config values::

        5 days
        10 minutes

    :param key: The config value key without the `SECURITY_` prefix
    :param app: Optional application to inspect. Defaults to Flask's
                `current_app`
    """
    txt = config_value(key, app=app)
    values = txt.split()
    return timedelta(**{values[1]: int(values[0])})


def send_mail(subject, recipient, template, **context):
    """Send an email.

    :param subject: Email subject
    :param recipient: Email recipient
    :param template: The name of the email template
    :param context: The context to render the template with

    This formats the email and passes it off to :class:`.MailUtil` to actually send the
    message.
    """

    context.setdefault("security", _security)
    context.update(_security._run_ctx_processor("mail"))

    body = None
    html = None
    template_path = f"security/email/{template}"
    if config_value("EMAIL_PLAINTEXT"):
        body = _security.render_template(f"{template_path}.txt", **context)
    if config_value("EMAIL_HTML"):
        html = _security.render_template(f"{template_path}.html", **context)

    subject = localize_callback(subject)

    sender = config_value("EMAIL_SENDER")
    if isinstance(sender, LocalProxy):
        sender = sender._get_current_object()

    _security._mail_util.send_mail(
        template,
        subject,
        recipient,
        sender,
        body,
        html,
        **context,
    )


def get_token_status(token, serializer, max_age=None, return_data=False):
    """Get the status of a token.

    :param token: The token to check
    :param serializer: The name of the serializer. Can be one of the
                       following: ``confirm``, ``login``, ``reset``
    :param max_age: The name of the max age config option. Can be one of
                    the following: ``CONFIRM_EMAIL``, ``LOGIN``,
                    ``RESET_PASSWORD``

    .. deprecated:: 5.0.0
    """
    warnings.warn(
        "'get_token_status' is deprecated - use check_and_get_token_status instead",
        DeprecationWarning,
        stacklevel=2,
    )
    serializer = getattr(_security, serializer + "_serializer")
    max_age = get_max_age(max_age)
    user, data = None, None
    expired, invalid = False, False

    try:
        data = serializer.loads(token, max_age=max_age)
    except SignatureExpired:
        d, data = serializer.loads_unsafe(token)
        expired = True
    except (BadSignature, TypeError, ValueError):
        invalid = True

    if data:
        user = _datastore.find_user(fs_uniquifier=data[0])

    expired = expired and (user is not None)

    if return_data:
        return expired, invalid, user, data
    else:
        return expired, invalid, user


def check_and_get_token_status(
    token: str, serializer_name: str, within: timedelta
) -> tuple[bool, bool, t.Any]:
    """Get the status of a token and return data.

    :param token: The token to check
    :param serializer_name: The name of the serializer. Can be one of the
                       following: ``confirm``, ``login``, ``reset``, ``us_setup``
                       ``remember``, ``two_factor_validity``, ``wan``
    :param within: max age - passed as a timedelta

    :return: a tuple of (expired, invalid, data)

    .. versionadded:: 3.4.0
    """
    serializer = getattr(_security, serializer_name + "_serializer")
    max_age = within.total_seconds()
    data = None
    expired, invalid = False, False

    try:
        data = serializer.loads(token, max_age=max_age)
    except SignatureExpired:
        d, data = serializer.loads_unsafe(token)
        expired = True
    except (BadSignature, TypeError, ValueError):
        invalid = True

    return expired, invalid, data


def get_identity_attributes(app: Flask | None = None) -> list[str]:
    # Return list of keys of identity attributes
    # Is it possible to not have any?
    app = app or current_app
    iattrs = app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"]
    if iattrs:
        return [[*f][0] for f in iattrs]
    return []


def get_identity_attribute(attr: str, app: Flask | None = None) -> dict[str, t.Any]:
    """Given a user_identity_attribute, return the defining dict.
    A bit annoying since USER_IDENTITY_ATTRIBUTES is a list of dict
    where each dict has just one key.
    """
    app = app or current_app
    iattrs = app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"]
    if iattrs:
        details = [
            mapping[attr] for mapping in iattrs if list(mapping.keys())[0] == attr
        ]
        if details:
            return details[0]
    return {}


def lookup_identity(identity):
    """
    Lookup identity in DB.
    This loops through, in order, :py:data:`SECURITY_USER_IDENTITY_ATTRIBUTES`,
    and first calls the mapper function to normalize.
    Then the db.find_user is called on the specified user model attribute.
    """
    for mapping in config_value("USER_IDENTITY_ATTRIBUTES"):
        attr = list(mapping.keys())[0]
        details = mapping[attr]
        idata = details["mapper"](identity)
        if idata:
            user = _datastore.find_user(
                case_insensitive=details.get("case_insensitive", False), **{attr: idata}
            )
            return user
    return None


def uia_phone_mapper(identity: str) -> str | None:
    """Used to normalize a phone number. This is a simple proxy
    to :py:meth:`PhoneUtil.get_canonical_form`

    See :py:data:`SECURITY_USER_IDENTITY_ATTRIBUTES`.

    .. versionadded:: 3.4.0
    """
    ph = _security._phone_util.get_canonical_form(identity)
    return ph


def uia_email_mapper(identity: str) -> str | None:
    """Used to normalize identity as an email.
    This is a simple proxy
    to :py:meth:`MailUtil.normalize`

    :return: Normalized email or None if not valid email.

    See :py:data:`SECURITY_USER_IDENTITY_ATTRIBUTES`.

    .. versionadded:: 3.4.0
    """

    try:
        return _security._mail_util.normalize(identity)
    except ValueError:
        return None


def uia_username_mapper(identity: str) -> str | None:
    """Used to normalize a username. This is a simple proxy
    to :py:meth:`UsernameUtil.normalize`

    See :py:data:`SECURITY_USER_IDENTITY_ATTRIBUTES`.

    .. versionadded:: 4.1.0
    """
    return _security._username_util.normalize(identity)


def use_double_hash(password_hash=None):
    """Return a bool indicating whether a password should be hashed twice."""
    # Default to plaintext for backward compatibility with
    # :py:data:`SECURITY_PASSWORD_SINGLE_HASH` = False
    single_hash = config_value("PASSWORD_SINGLE_HASH") or {"plaintext"}

    if password_hash is None:
        scheme = config_value("PASSWORD_HASH")
    else:
        scheme = _pwd_context.identify(password_hash)

    return not (single_hash is True or scheme in single_hash)


def csrf_cookie_handler(response: Response) -> Response:
    """Called at end of every request.
    Uses session to track state (set/clear)

    Ideally we just need to set this once - however by default
    Flask-WTF has a time-out on these tokens governed by *WTF_CSRF_TIME_LIMIT*.
    While we could set that to None - and OWASP implies this is fine - that might
    not be agreeable to everyone.
    So as a basic usability hack - we check if it is expired and re-generate so at least
    the user doesn't have to log out and back in (just refresh).
    We also support a *CSRF_COOKIE_REFRESH_EACH_REQUEST* analogous to Flask's
    *SESSION_REFRESH_EACH_REQUEST*

    It is of course removed on logout/session end.
    Other info on web suggests replacing on every POST and accepting up to 'age' ago.
    """
    csrf_cookie = config_value("CSRF_COOKIE")
    csrf_cookie_name = config_value("CSRF_COOKIE_NAME")
    if not csrf_cookie_name:
        return response

    op = session.get("fs_cc", None)
    if not op:
        remember_cookie_name = current_app.config.get(
            "REMEMBER_COOKIE_NAME", REMEMBER_COOKIE_NAME
        )
        has_remember_cookie = (
            remember_cookie_name in request.cookies
            and session.get("remember") != "clear"
        )
        # Set cookie if successfully logged in with flask_login's remember cookie
        if has_remember_cookie and is_user_authenticated(current_user):
            op = "set"
        else:
            return response

    if op == "clear":
        # Alas delete_cookie only accepts some of the keywords set_cookie does
        allowed = ["path", "domain", "secure", "httponly", "samesite"]
        args = {k: csrf_cookie.get(k) for k in allowed if k in csrf_cookie}
        response.delete_cookie(csrf_cookie_name, **args)
        session.pop("fs_cc")
        return response

    # Send a cookie if any of:
    # 1) CSRF_COOKIE_REFRESH_EACH_REQUEST is true
    # 2) fs_cc == "set" - this is on first login
    # 3) existing cookie has expired
    send = False
    if op == "set":
        send = True
        session["fs_cc"] = "sent"
    elif config_value("CSRF_COOKIE_REFRESH_EACH_REQUEST"):
        send = True
    elif current_app.config["WTF_CSRF_TIME_LIMIT"]:
        current_cookie = request.cookies.get(csrf_cookie_name, None)
        if current_cookie:
            # Let's make sure it isn't expired if app doesn't set TIME_LIMIT to None.
            try:
                csrf.validate_csrf(current_cookie)
            except ValidationError:
                send = True

    if send:
        response.set_cookie(csrf_cookie_name, value=csrf.generate_csrf(), **csrf_cookie)
    return response


def base_render_json(
    form: FlaskForm,
    include_user: bool = True,
    include_auth_token: bool = False,
    additional: dict[str, t.Any] | None = None,
    error_status_code: int = 400,
) -> ResponseValue:
    """
    This method is called by all views that return JSON responses.
    This fills in the response and then calls :meth:`.Security.render_json`
    which can be overridden by the app.
    """
    user = getattr(form, "user", None)
    if form.errors:
        code = error_status_code
        # wtforms 3.0 introduces form-level errors - these show up as part of the
        # errors dict with a key of 'None'
        payload = json_error_response(field_errors=form.errors)
    else:
        code = 200
        payload = dict()
        if user:
            # This allows anonymous GETs via JSON
            if include_user:
                payload["user"] = user.get_security_payload()

            if include_auth_token:
                # view willing to return auth_token - check behavior config
                if (
                    config_value("BACKWARDS_COMPAT_AUTH_TOKEN")
                    or "include_auth_token" in request.args
                ):
                    try:
                        token = user.get_auth_token()
                    except ValueError:
                        # application has fs_token_uniquifier attribute but it
                        # hasn't been initialized. Since we are in a request context
                        # we can do that here.
                        _datastore.set_token_uniquifier(user)
                        after_this_request(view_commit)
                        token = user.get_auth_token()
                    payload["user"]["authentication_token"] = token

        # Return csrf_token on each JSON response - just as every form
        # has it rendered.
        payload["csrf_token"] = csrf.generate_csrf()
        if additional:
            payload.update(additional)

    return _security._render_json(payload, code, None, user)


def simple_render_json(
    additional: dict[str, t.Any] | None = None,
) -> ResponseValue:
    payload = dict(csrf_token=csrf.generate_csrf())
    if additional:
        payload.update(additional)
    return _security._render_json(payload, 200, None, None)


def default_want_json(req):
    """Return True if response should be in json
    N.B. do not call this directly - use security._want_json()

    :param req: Flask/Werkzeug Request
    """
    if req.is_json:
        return True
    # TODO should this handle json sub-types?
    accept_mimetypes = req.accept_mimetypes
    if not hasattr(req.accept_mimetypes, "best"):  # pragma: no cover
        # Alright. we don't have the best property, lets add it ourselves.
        # This is for quart compatibility
        accept_mimetypes.best = best
    if accept_mimetypes.best == "application/json":
        return True
    return False


def json_error_response(
    errors: str | list | None = None,
    field_errors: dict[str | None, list] | None = None,
) -> dict[str, t.Any]:
    """Helper to create an error response.

    The "errors" key holds a simple list of errors - which is made up of any passed
    errors (either a string or list) as well as the (localized) error msgs from the
    passed in field_errors.

    The "field_errors" key which is exactly what is returned from WTForms - namely
    a dict of field-name: msg. For form-level errors (WTForms 3.0) the 'field-name' is
    None - which alas means it isn't sortable and Flask's default JSONProvider
    sorts keys - so we change that to '__all__' which is what django uses
    apparently and was suggested as part of WTForms 3.0.
    """
    response_json: dict[str, list | dict[str, list]] = dict()
    plain_errors = []
    if errors:
        if isinstance(errors, str):
            plain_errors = [errors]
        elif isinstance(errors, list):
            plain_errors = errors
        else:
            raise TypeError("The errors argument should be either a str or list.")
    if field_errors:
        # This is default from WTForms - a dictionary of field name and list of errors
        # we return that, as well as create a simple list of errors.
        for e in field_errors.values():
            plain_errors.extend(e)
        if None in field_errors.keys():
            # Ugh - wtforms decided to use None as a key - which json
            # a) can't sort
            # b) converts to "null"
            # Issue filed - maybe they will change it
            field_errors[""] = field_errors[None]
            del field_errors[None]
        response_json["field_errors"] = field_errors  # type: ignore
    response_json["errors"] = plain_errors

    return response_json


def default_render_template(*args, **kwargs):
    return render_template(*args, **kwargs)


class SmsSenderBaseClass(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def send_sms(
        self, from_number: str, to_number: str, msg: str
    ) -> None:  # pragma: no cover
        """Abstract method for sending sms messages

        .. versionadded:: 3.2.0
        """
        return


class DummySmsSender(SmsSenderBaseClass):
    def send_sms(self, from_number, to_number, msg):  # pragma: no cover
        """Do nothing."""
        return


class SmsSenderFactory:
    senders: dict[str, t.Type[SmsSenderBaseClass]] = {"Dummy": DummySmsSender}

    @classmethod
    def createSender(cls, name, *args, **kwargs):
        """Initialize an SMS sender.

        :param name: Name as registered in SmsSenderFactory:senders (e.g. 'Twilio')

        .. versionadded:: 3.2.0
        """
        return cls.senders[name](*args, **kwargs)


try:  # pragma: no cover
    from twilio.rest import Client

    class TwilioSmsSender(SmsSenderBaseClass):
        def __init__(self):
            super().__init__()
            self.account_sid = config_value("SMS_SERVICE_CONFIG")["ACCOUNT_SID"]
            self.auth_token = config_value("SMS_SERVICE_CONFIG")["AUTH_TOKEN"]

        def send_sms(self, from_number, to_number, msg):
            """Send message via twilio account."""
            client = Client(self.account_sid, self.auth_token)
            client.messages.create(to=to_number, from_=from_number, body=msg)

    SmsSenderFactory.senders["Twilio"] = TwilioSmsSender
except Exception:
    pass


def password_length_validator(password: str) -> list[str] | None:
    """Test password for length.

    :param password: Plain text password to check

    :return: ``None`` if password conforms to length requirements,
     a list of error/suggestions if not.

    .. versionadded:: 3.4.0

    """
    if len(password) < config_value("PASSWORD_LENGTH_MIN") or len(password) > 128:
        return [
            get_message(
                "PASSWORD_INVALID_LENGTH", length=config_value("PASSWORD_LENGTH_MIN")
            )[0]
        ]
    return None


def password_complexity_validator(
    password: str, is_register: bool, **kwargs: t.Any
) -> list[str] | None:
    """Test password for complexity.

    Currently just supports 'zxcvbn'.

    :param password: Plain text password to check
    :param is_register: if True then kwargs are arbitrary additional info. (e.g.
        info from a registration form). If False, must be a SINGLE key "user" that
        corresponds to the current_user. All string values will be extracted and
        sent to the complexity checker.
    :param kwargs:

    :return: ``None`` if password is complex enough, a list of error/suggestions if not.
        Be aware that zxcvbn does not (easily) provide a way to localize messages.

    .. versionadded:: 3.4.0
    """

    if config_value("PASSWORD_COMPLEXITY_CHECKER") == "zxcvbn":
        import zxcvbn

        user_info: list[t.Any] = []
        if not is_register:
            for v in kwargs["user"].__dict__.values():
                if v and isinstance(v, str):
                    user_info.append(v)
        else:
            # This is usually all register form values that are in the user_model
            if kwargs:
                user_info = list(kwargs.values())
        results = zxcvbn.zxcvbn(password, user_inputs=user_info)
        if results["score"] >= config_value("ZXCVBN_MINIMUM_SCORE"):
            return None
        # Should we return suggestions? Default forms don't really know what to do.
        if results["feedback"]["warning"]:
            # Note that these come from zxcvbn and
            # aren't localizable via Flask-Security
            return [results["feedback"]["warning"]]
        return [get_message("PASSWORD_TOO_SIMPLE")[0]]
    else:
        return None


def password_breached_validator(password: str) -> list[str] | None:
    """Check if password on breached list.
    Does nothing unless :py:data:`SECURITY_PASSWORD_CHECK_BREACHED` is set.
    If password is found on the breached list, return an error if the count is
    greater than or equal to :py:data:`SECURITY_PASSWORD_BREACHED_COUNT`.
    Uses :meth:`pwned`.

    :param password: Plain text password to check

    :return: ``None`` if password passes breached tests, else a list of error messages.

    .. versionadded:: 3.4.0
    """
    if pwn := config_value("PASSWORD_CHECK_BREACHED"):
        try:
            cnt = pwned(password)
            if cnt >= config_value("PASSWORD_BREACHED_COUNT"):
                return [get_message("PASSWORD_BREACHED")[0]]
        except Exception:
            if pwn == "strict":
                return [get_message("PASSWORD_BREACHED_SITE_ERROR")[0]]
    return None


def pwned(password: str) -> int:
    """
    Check password against pwnedpasswords API using k-Anonymity.
    https://haveibeenpwned.com/API/v3

    :return: Count of password in DB (0 means hasn't been compromised)

    Can raise HTTPError

    .. versionadded:: 3.4.0
    """

    def convert_password_tuple(value):
        hash_suffix, count = value.split(":")
        return hash_suffix, int(count)

    sha1 = hashlib.sha1(password.encode("utf8")).hexdigest()

    req = urllib.request.Request(
        url=f"https://api.pwnedpasswords.com/range/{sha1[:5].upper()}",
        headers={"User-Agent": "Flask-Security (Python)"},
    )
    # Might raise HTTPError
    with urllib.request.urlopen(req) as f:
        response = f.read()

    raw = response.decode("utf-8-sig")

    entries = dict(map(convert_password_tuple, raw.upper().split("\r\n")))
    return entries.get(sha1[5:].upper(), 0)


def handle_already_auth(form, payload=None):
    """
    Allow already authenticated users. For GET this is useful for
    single-page-applications on refresh - session still active but need to
    access user info and csrf-token.
    For GET with forms - redirect to POST_LOGIN_VIEW.
    For POST - redirects to POST_LOGIN_VIEW (forms) or returns 400 (json).

    This does NOT use get_post_login_redirect() so that it doesn't look at
    'next' - which can cause infinite redirect loops
    (see test_basic::test_authenticated_loop)

    While it's tempting to try to logout the current user and login the
    new requested user - that simply doesn't work with CSRF.
    """
    if _security._want_json(request):
        if request.method == "POST":
            payload = json_error_response(
                errors=get_message("ANONYMOUS_USER_REQUIRED")[0]
            )
            return _security._render_json(payload, 400, None, None)
        else:
            form.user = current_user
            return base_render_json(form, additional=payload)
    else:
        return redirect(get_url(config_value("POST_LOGIN_VIEW")))
