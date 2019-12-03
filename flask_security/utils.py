# -*- coding: utf-8 -*-
"""
    flask_security.utils
    ~~~~~~~~~~~~~~~~~~~~

    Flask-Security utils module

    :copyright: (c) 2012-2019 by Matt Wright.
    :copyright: (c) 2019 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""
import abc
import base64
from functools import partial
import hashlib
import hmac
import sys
import warnings
from contextlib import contextmanager
from datetime import timedelta

from flask import current_app, flash, request, session, url_for
from flask.json import JSONEncoder
from flask.signals import message_flashed
from flask_login import login_user as _login_user
from flask_login import logout_user as _logout_user
from flask_mail import Message
from flask_principal import AnonymousIdentity, Identity, identity_changed, Need
from flask_wtf import csrf
from wtforms import ValidationError
from itsdangerous import BadSignature, SignatureExpired
from speaklater import is_lazy_string
from werkzeug.local import LocalProxy
from werkzeug.datastructures import MultiDict
from . import quart_compat
from .signals import (
    login_instructions_sent,
    reset_password_instructions_sent,
    user_registered,
)

try:  # pragma: no cover
    from urlparse import parse_qsl, urlsplit, urlunsplit
    from urllib import urlencode
except ImportError:  # pragma: no cover
    from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode

# Convenient references
_security = LocalProxy(lambda: current_app.extensions["security"])

_datastore = LocalProxy(lambda: _security.datastore)

_pwd_context = LocalProxy(lambda: _security.pwd_context)

_hashing_context = LocalProxy(lambda: _security.hashing_context)

localize_callback = LocalProxy(lambda: _security.i18n_domain.gettext)

PY3 = sys.version_info[0] == 3

if PY3:  # pragma: no cover
    string_types = (str,)  # noqa
    text_type = str  # noqa
else:  # pragma: no cover
    string_types = (basestring,)  # noqa
    text_type = unicode  # noqa

FsPermNeed = partial(Need, "fsperm")
FsPermNeed.__doc__ = """A need with the method preset to `"fsperm"`."""


def _(translate):
    """Identity function to mark strings for translation."""
    return translate


def find_csrf_field_name():
    """
    We need to clear it on logout (since that isn't being done by Flask-WTF).
    The field name is configurable withing Flask-WTF as well as being
    overridable.
    We take the field name from the login_form as set by the configuration.
    """
    form = _security.login_form(MultiDict([]))
    if hasattr(form.meta, "csrf_field_name"):
        return form.meta.csrf_field_name
    return None


def login_user(user, remember=None):
    """Perform the login routine.

    If *SECURITY_TRACKABLE* is used, make sure you commit changes after this
    request (i.e. ``app.security.datastore.commit()``).

    :param user: The user to login
    :param remember: Flag specifying if the remember cookie should be set.
                     Defaults to ``False``
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

    session["fs_cc"] = "set"

    identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))
    return True


def logout_user():
    """Logs out the current user.

    This will also clean up the remember me cookie if it exists.

    This sends an ``identity_changed`` signal to note that the current
    identity is now the `AnonymousIdentity`
    """

    for key in ("identity.name", "identity.auth_type"):
        session.pop(key, None)

    # Clear csrf token between sessions.
    # Ideally this would be handled by Flask-WTF but...
    # We don't clear entire session since Flask-Login seems to like having it.
    csrf_field_name = find_csrf_field_name()
    if csrf_field_name:
        session.pop(csrf_field_name, None)
    session["fs_cc"] = "clear"
    identity_changed.send(
        current_app._get_current_object(), identity=AnonymousIdentity()
    )
    _logout_user()


def get_hmac(password):
    """Returns a Base64 encoded HMAC+SHA512 of the password signed with
    the salt specified by *SECURITY_PASSWORD_SALT*.

    :param password: The password to sign
    """
    salt = _security.password_salt

    if salt is None:
        raise RuntimeError(
            "The configuration value `SECURITY_PASSWORD_SALT` must "
            "not be None when the value of `SECURITY_PASSWORD_HASH` is "
            'set to "%s"' % _security.password_hash
        )

    h = hmac.new(encode_string(salt), encode_string(password), hashlib.sha512)
    return base64.b64encode(h.digest())


def verify_password(password, password_hash):
    """Returns ``True`` if the password matches the supplied hash.

    :param password: A plaintext password to verify
    :param password_hash: The expected hash value of the password
                          (usually from your database)
    """
    if use_double_hash(password_hash):
        password = get_hmac(password)

    return _pwd_context.verify(password, password_hash)


def verify_and_update_password(password, user):
    """Returns ``True`` if the password is valid for the specified user.

    Additionally, the hashed password in the database is updated if the
    hashing algorithm happens to have changed.

    N.B. you MUST call DB commit if you are using a session-based datastore
    (such as SqlAlchemy) since the user instance might have been altered
    (i.e. ``app.security.datastore.commit()``).
    This is usually handled in the view.

    :param password: A plaintext password to verify
    :param user: The user to verify against
    """
    if use_double_hash(user.password):
        verified = _pwd_context.verify(get_hmac(password), user.password)
    else:
        # Try with original password.
        verified = _pwd_context.verify(password, user.password)

    if verified and _pwd_context.needs_update(user.password):
        user.password = hash_password(password)
        _datastore.put(user)
    return verified


def encrypt_password(password):
    """Encrypt the specified plaintext password.

    It uses the configured encryption options.

    .. deprecated:: 2.0.2
       Use :func:`hash_password` instead.

    :param password: The plaintext password to encrypt
    """
    warnings.warn(
        "Please use hash_password instead of encrypt_password.", DeprecationWarning
    )
    return hash_password(password)


def hash_password(password):
    """Hash the specified plaintext password.

    Unless the hash algorithm (as specified by `SECURITY_PASSWORD_HASH`) is listed in
    the configuration variable `SECURITY_PASSWORD_SINGLE_HASH`,
    perform a double hash - first create an HMAC from the plaintext password
    and the value of `SECURITY_PASSWORD_SALT`,
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
            _security.password_hash, {}
        )
    )


def encode_string(string):
    """Encodes a string to bytes, if it isn't already.

    :param string: The string to encode"""

    if isinstance(string, text_type):
        string = string.encode("utf-8")
    return string


def hash_data(data):
    return _hashing_context.hash(encode_string(data))


def verify_hash(hashed_data, compare_data):
    return _hashing_context.verify(encode_string(compare_data), hashed_data)


def do_flash(message, category=None):
    """Flash a message depending on if the `FLASH_MESSAGES` configuration
    value is set.

    :param message: The flash message
    :param category: The flash message category
    """
    if config_value("FLASH_MESSAGES"):
        flash(message, category)


def get_url(endpoint_or_url, qparams=None):
    """Returns a URL if a valid endpoint is found. Otherwise, returns the
    provided value.

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
        if _security.redirect_host:
            url = transform_url(
                endpoint_or_url, qparams, netloc=_security.redirect_host
            )
        else:
            url = transform_url(endpoint_or_url, qparams)

        return url


def slash_url_suffix(url, suffix):
    """Adds a slash either to the beginning or the end of a suffix
    (which is to be appended to a URL), depending on whether or not
    the URL ends with a slash."""

    return url.endswith("/") and ("%s/" % suffix) or ("/%s" % suffix)


def transform_url(url, qparams=None, **kwargs):
    """ Modify url

    :param url: url to transform (can be relative)
    :param qparams: additional query params to add to end of url
    :param kwargs: pieces of URL to modify - e.g. netloc=localhost:8000
    :return: Modified URL

    .. versionadded:: 3.2.0
    """
    if not url:
        return url
    link_parse = urlsplit(url)
    if qparams:
        current_query = dict(parse_qsl(link_parse.query))
        current_query.update(qparams)
        link_parse = link_parse._replace(query=urlencode(current_query))
    return urlunsplit(link_parse._replace(**kwargs))


def get_security_endpoint_name(endpoint):
    return "%s.%s" % (_security.blueprint_name, endpoint)


def url_for_security(endpoint, **values):
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
    return url_for(endpoint, **values)


def validate_redirect_url(url):
    if url is None or url.strip() == "":
        return False
    url_next = urlsplit(url)
    url_base = urlsplit(request.host_url)
    if (url_next.netloc or url_next.scheme) and url_next.netloc != url_base.netloc:
        return False
    return True


def get_post_action_redirect(config_key, declared=None):
    urls = [
        get_url(request.args.get("next", None)),
        get_url(request.form.get("next", None)),
        find_redirect(config_key),
    ]
    if declared:
        urls.insert(0, declared)
    for url in urls:
        if validate_redirect_url(url):
            return url


def get_post_login_redirect(declared=None):
    return get_post_action_redirect("SECURITY_POST_LOGIN_VIEW", declared)


def get_post_register_redirect(declared=None):
    return get_post_action_redirect("SECURITY_POST_REGISTER_VIEW", declared)


def get_post_logout_redirect(declared=None):
    return get_post_action_redirect("SECURITY_POST_LOGOUT_VIEW", declared)


def find_redirect(key):
    """Returns the URL to redirect to after a user logs in successfully.

    :param key: The session or application configuration key to search for
    """
    rv = (
        get_url(session.pop(key.lower(), None))
        or get_url(current_app.config[key.upper()] or None)
        or "/"
    )
    return rv


def get_config(app):
    """Conveniently get the security configuration for the specified
    application without the annoying 'SECURITY_' prefix.

    :param app: The application to inspect
    """
    items = app.config.items()
    prefix = "SECURITY_"

    def strip_prefix(tup):
        return (tup[0].replace("SECURITY_", ""), tup[1])

    return dict([strip_prefix(i) for i in items if i[0].startswith(prefix)])


def get_message(key, **kwargs):
    rv = config_value("MSG_" + key)
    return localize_callback(rv[0], **kwargs), rv[1]


def config_value(key, app=None, default=None):
    """Get a Flask-Security configuration value.

    :param key: The configuration key without the prefix `SECURITY_`
    :param app: An optional specific application to inspect. Defaults to
                Flask's `current_app`
    :param default: An optional default value if the value is not set
    """
    app = app or current_app
    return get_config(app).get(key.upper(), default)


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
    """Send an email via the Flask-Mail extension.

    :param subject: Email subject
    :param recipient: Email recipient
    :param template: The name of the email template
    :param context: The context to render the template with
    """

    context.setdefault("security", _security)
    context.update(_security._run_ctx_processor("mail"))

    sender = _security.email_sender
    if isinstance(sender, LocalProxy):
        sender = sender._get_current_object()

    msg = Message(subject, sender=sender, recipients=[recipient])

    ctx = ("security/email", template)
    if config_value("EMAIL_PLAINTEXT"):
        msg.body = _security.render_template("%s/%s.txt" % ctx, **context)
    if config_value("EMAIL_HTML"):
        msg.html = _security.render_template("%s/%s.html" % ctx, **context)

    if _security._send_mail_task:
        _security._send_mail_task(msg)
        return

    mail = current_app.extensions.get("mail")
    mail.send(msg)


def get_token_status(token, serializer, max_age=None, return_data=False):
    """Get the status of a token.

    :param token: The token to check
    :param serializer: The name of the seriailzer. Can be one of the
                       following: ``confirm``, ``login``, ``reset``
    :param max_age: The name of the max age config option. Can be on of
                    the following: ``CONFIRM_EMAIL``, ``LOGIN``,
                    ``RESET_PASSWORD``
    """
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
        user = _datastore.find_user(id=data[0])

    expired = expired and (user is not None)

    if return_data:
        return expired, invalid, user, data
    else:
        return expired, invalid, user


def get_identity_attributes(app=None):
    app = app or current_app
    attrs = app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"]
    try:
        attrs = [f.strip() for f in attrs.split(",")]
    except AttributeError:
        pass
    return attrs


def use_double_hash(password_hash=None):
    """Return a bool indicating whether a password should be hashed twice."""
    # Default to plaintext for backward compatibility with
    # SECURITY_PASSWORD_SINGLE_HASH = False
    single_hash = config_value("PASSWORD_SINGLE_HASH") or {"plaintext"}

    if password_hash is None:
        scheme = _security.password_hash
    else:
        scheme = _pwd_context.identify(password_hash)

    return not (single_hash is True or scheme in single_hash)


def csrf_cookie_handler(response):
    """ Called at end of every request.
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
    if not csrf_cookie or not csrf_cookie["key"]:
        return response

    op = session.get("fs_cc", None)
    if not op:
        return response

    if op == "clear":
        response.delete_cookie(
            csrf_cookie["key"],
            path=csrf_cookie.get("path", "/"),
            domain=csrf_cookie.get("domain", None),
        )
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
        current_cookie = request.cookies.get(csrf_cookie["key"], None)
        if current_cookie:
            # Lets make sure it isn't expired if app doesn't set TIME_LIMIT to None.
            try:
                csrf.validate_csrf(current_cookie)
            except ValidationError:
                send = True

    if send:
        kwargs = {k: v for k, v in csrf_cookie.items()}
        kwargs.pop("key")
        kwargs["value"] = csrf.generate_csrf()
        response.set_cookie(csrf_cookie["key"], **kwargs)
    return response


def default_want_json(req):
    """ Return True if response should be in json
    N.B. do not call this directly - use security.want_json()

    :param req: Flask/Werkzeug Request
    """
    if req.is_json:
        return True
    # TODO should this handle json sub-types?
    if not hasattr(req.accept_mimetypes, "best"):  # pragma: no cover
        # Alright. we dont have the best property, lets add it ourselves.
        # This is for quart compatibility
        setattr(req.accept_mimetypes, "best", quart_compat.best)
    if req.accept_mimetypes.best == "application/json":
        return True
    return False


def json_error_response(errors):
    """ Helper to create an error response that adheres to the openapi spec.
    """
    # Python 2 and 3 compatibility for checking if something is a string.
    try:  # pragma: no cover
        basestring
        string_type_check = (basestring, unicode)
    except NameError:  # pragma: no cover
        string_type_check = str

    if isinstance(errors, string_type_check):
        # When the errors is a string, use the response/error/message format
        response_json = dict(error=errors)
    elif isinstance(errors, dict):
        # When the errors is a dict, use the DefaultJsonErrorResponse
        # (response/errors/name/messages) format
        response_json = dict(errors=errors)
    else:
        raise TypeError("The errors argument should be either a str or dict.")

    return response_json


class FsJsonEncoder(JSONEncoder):
    """  Flask-Security JSON encoder.
    Extends Flask's JSONencoder to handle lazy-text.

    .. versionadded:: 3.3.0
    """

    def default(self, obj):
        if is_lazy_string(obj):
            return str(obj)
        else:
            return JSONEncoder.default(self, obj)


@contextmanager
def capture_passwordless_login_requests():
    login_requests = []

    def _on(app, **data):
        login_requests.append(data)

    login_instructions_sent.connect(_on)

    try:
        yield login_requests
    finally:
        login_instructions_sent.disconnect(_on)


@contextmanager
def capture_registrations():
    """Testing utility for capturing registrations.

    :param confirmation_sent_at: An optional datetime object to set the
                                 user's `confirmation_sent_at` to
    """
    registrations = []

    def _on(app, **data):
        registrations.append(data)

    user_registered.connect(_on)

    try:
        yield registrations
    finally:
        user_registered.disconnect(_on)


@contextmanager
def capture_reset_password_requests(reset_password_sent_at=None):
    """Testing utility for capturing password reset requests.

    :param reset_password_sent_at: An optional datetime object to set the
                                   user's `reset_password_sent_at` to
    """
    reset_requests = []

    def _on(app, **data):
        reset_requests.append(data)

    reset_password_instructions_sent.connect(_on)

    try:
        yield reset_requests
    finally:
        reset_password_instructions_sent.disconnect(_on)


@contextmanager
def capture_flashes():
    """Testing utility for capturing flashes."""
    flashes = []

    def _on(app, **data):
        flashes.append(data)

    message_flashed.connect(_on)

    try:
        yield flashes
    finally:
        message_flashed.disconnect(_on)


class SmsSenderBaseClass(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        pass

    @abc.abstractmethod
    def send_sms(self, from_number, to_number, msg):  # pragma: no cover
        """ Abstract method for sending sms messages

        .. versionadded:: 3.2.0
        """
        return


class DummySmsSender(SmsSenderBaseClass):
    def send_sms(self, from_number, to_number, msg):  # pragma: no cover
        """ Do nothing. """
        return


class SmsSenderFactory(object):
    senders = {"Dummy": DummySmsSender}

    @classmethod
    def createSender(cls, name, *args, **kwargs):
        """ Initialize an SMS sender.

        :param name: Name as registered in SmsSenderFactory:senders (e.g. 'Twilio')

        .. versionadded:: 3.2.0
        """
        return cls.senders[name](*args, **kwargs)


try:  # pragma: no cover
    from twilio.rest import Client

    class TwilioSmsSender(SmsSenderBaseClass):
        def __init__(self):
            self.account_sid = config_value("TWO_FACTOR_SMS_SERVICE_CONFIG")[
                "ACCOUNT_SID"
            ]
            self.auth_token = config_value("TWO_FACTOR_SMS_SERVICE_CONFIG")[
                "AUTH_TOKEN"
            ]

        def send_sms(self, from_number, to_number, msg):
            """ Send message via twilio account. """
            client = Client(self.account_sid, self.auth_token)
            client.messages.create(to=to_number, from_=from_number, body=msg)

    SmsSenderFactory.senders["Twilio"] = TwilioSmsSender
except Exception:
    pass
