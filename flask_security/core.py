# -*- coding: utf-8 -*-
"""
    flask_security.core
    ~~~~~~~~~~~~~~~~~~~

    Flask-Security core module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2017 by CERN.
    :copyright: (c) 2017 by ETH Zurich, Swiss Data Science Center.
    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from datetime import datetime, timedelta
import warnings
import sys

import pkg_resources
from flask import _request_ctx_stack, current_app, render_template
from flask_babelex import Domain
from flask_login import AnonymousUserMixin, LoginManager
from flask_login import UserMixin as BaseUserMixin
from flask_login import current_user
from flask_principal import Identity, Principal, RoleNeed, UserNeed, identity_loaded
from itsdangerous import URLSafeTimedSerializer
from passlib.context import CryptContext
from werkzeug.datastructures import ImmutableList
from werkzeug.local import LocalProxy, Local

from .decorators import (
    default_reauthn_handler,
    default_unauthn_handler,
    default_unauthz_handler,
)
from .forms import (
    ChangePasswordForm,
    ConfirmRegisterForm,
    ForgotPasswordForm,
    LoginForm,
    PasswordlessLoginForm,
    RegisterForm,
    ResetPasswordForm,
    SendConfirmationForm,
    TwoFactorVerifyCodeForm,
    TwoFactorSetupForm,
    TwoFactorVerifyPasswordForm,
    TwoFactorRescueForm,
    VerifyForm,
)
from .phone_util import PhoneUtil
from .twofactor import tf_send_security_token
from .unified_signin import (
    UnifiedSigninForm,
    UnifiedSigninSetupForm,
    UnifiedSigninSetupValidateForm,
    UnifiedVerifyForm,
    us_send_security_token,
)
from .totp import Totp
from .utils import _
from .utils import config_value as cv
from .utils import (
    FsJsonEncoder,
    FsPermNeed,
    csrf_cookie_handler,
    default_want_json,
    default_password_validator,
    get_config,
    get_identity_attributes,
    get_message,
    hash_data,
    localize_callback,
    send_mail,
    string_types,
    uia_email_mapper,
    uia_phone_mapper,
    url_for_security,
    verify_and_update_password,
    verify_hash,
)
from .views import create_blueprint, default_render_json
from .cache import VerifyHashCache

# Convenient references
_security = LocalProxy(lambda: current_app.extensions["security"])
_datastore = LocalProxy(lambda: _security.datastore)
local_cache = Local()

# List of authentication mechanisms supported.
AUTHN_MECHANISMS = ("basic", "session", "token")


#: Default Flask-Security configuration
_default_config = {
    "BLUEPRINT_NAME": "security",
    "CLI_ROLES_NAME": "roles",
    "CLI_USERS_NAME": "users",
    "URL_PREFIX": None,
    "SUBDOMAIN": None,
    "FLASH_MESSAGES": True,
    "I18N_DOMAIN": "flask_security",
    "I18N_DIRNAME": pkg_resources.resource_filename("flask_security", "translations"),
    "PASSWORD_HASH": "bcrypt",
    "PASSWORD_SALT": None,
    "PASSWORD_SINGLE_HASH": {
        "django_argon2",
        "django_bcrypt_sha256",
        "django_pbkdf2_sha256",
        "django_pbkdf2_sha1",
        "django_bcrypt",
        "django_salted_md5",
        "django_salted_sha1",
        "django_des_crypt",
        "plaintext",
    },
    "PASSWORD_SCHEMES": [
        "bcrypt",
        "argon2",
        "des_crypt",
        "pbkdf2_sha256",
        "pbkdf2_sha512",
        "sha256_crypt",
        "sha512_crypt",
        # And always last one...
        "plaintext",
    ],
    "PASSWORD_HASH_OPTIONS": {},  # Deprecated at passlib 1.7
    "PASSWORD_HASH_PASSLIB_OPTIONS": {
        "argon2__rounds": 10  # 1.7.1 default is 2.
    },  # >= 1.7.1 method to pass options.
    "PASSWORD_LENGTH_MIN": 8,
    "PASSWORD_COMPLEXITY_CHECKER": None,
    "PASSWORD_CHECK_BREACHED": False,
    "PASSWORD_BREACHED_COUNT": 1,
    "DEPRECATED_PASSWORD_SCHEMES": ["auto"],
    "LOGIN_URL": "/login",
    "LOGOUT_URL": "/logout",
    "REGISTER_URL": "/register",
    "RESET_URL": "/reset",
    "CHANGE_URL": "/change",
    "CONFIRM_URL": "/confirm",
    "VERIFY_URL": "/verify",
    "TWO_FACTOR_SETUP_URL": "/tf-setup",
    "TWO_FACTOR_TOKEN_VALIDATION_URL": "/tf-validate",
    "TWO_FACTOR_QRCODE_URL": "/tf-qrcode",
    "TWO_FACTOR_RESCUE_URL": "/tf-rescue",
    "TWO_FACTOR_CONFIRM_URL": "/tf-confirm",
    "LOGOUT_METHODS": ["GET", "POST"],
    "POST_LOGIN_VIEW": "/",
    "POST_LOGOUT_VIEW": "/",
    "CONFIRM_ERROR_VIEW": None,
    "POST_REGISTER_VIEW": None,
    "POST_CONFIRM_VIEW": None,
    "POST_RESET_VIEW": None,
    "POST_CHANGE_VIEW": None,
    "POST_VERIFY_VIEW": None,
    "UNAUTHORIZED_VIEW": None,
    "RESET_ERROR_VIEW": None,
    "RESET_VIEW": None,
    "LOGIN_ERROR_VIEW": None,
    "REDIRECT_HOST": None,
    "REDIRECT_BEHAVIOR": None,
    "FORGOT_PASSWORD_TEMPLATE": "security/forgot_password.html",
    "LOGIN_USER_TEMPLATE": "security/login_user.html",
    "REGISTER_USER_TEMPLATE": "security/register_user.html",
    "RESET_PASSWORD_TEMPLATE": "security/reset_password.html",
    "CHANGE_PASSWORD_TEMPLATE": "security/change_password.html",
    "SEND_CONFIRMATION_TEMPLATE": "security/send_confirmation.html",
    "SEND_LOGIN_TEMPLATE": "security/send_login.html",
    "VERIFY_TEMPLATE": "security/verify.html",
    "TWO_FACTOR_VERIFY_CODE_TEMPLATE": "security/two_factor_verify_code.html",
    "TWO_FACTOR_SETUP_TEMPLATE": "security/two_factor_setup.html",
    "TWO_FACTOR_VERIFY_PASSWORD_TEMPLATE": "security/two_factor_verify_password.html",
    "CONFIRMABLE": False,
    "REGISTERABLE": False,
    "RECOVERABLE": False,
    "TRACKABLE": False,
    "PASSWORDLESS": False,
    "CHANGEABLE": False,
    "TWO_FACTOR": False,
    "SEND_REGISTER_EMAIL": True,
    "SEND_PASSWORD_CHANGE_EMAIL": True,
    "SEND_PASSWORD_RESET_EMAIL": True,
    "SEND_PASSWORD_RESET_NOTICE_EMAIL": True,
    "LOGIN_WITHIN": "1 days",
    "TWO_FACTOR_AUTHENTICATOR_VALIDITY": 120,
    "TWO_FACTOR_MAIL_VALIDITY": 300,
    "TWO_FACTOR_SMS_VALIDITY": 120,
    "CONFIRM_EMAIL_WITHIN": "5 days",
    "RESET_PASSWORD_WITHIN": "5 days",
    "LOGIN_WITHOUT_CONFIRMATION": False,
    "AUTO_LOGIN_AFTER_CONFIRM": True,
    "EMAIL_SENDER": LocalProxy(
        lambda: current_app.config.get("MAIL_DEFAULT_SENDER", "no-reply@localhost")
    ),
    "TWO_FACTOR_RESCUE_MAIL": "no-reply@localhost",
    "TOKEN_AUTHENTICATION_KEY": "auth_token",
    "TOKEN_AUTHENTICATION_HEADER": "Authentication-Token",
    "TOKEN_MAX_AGE": None,
    "CONFIRM_SALT": "confirm-salt",
    "RESET_SALT": "reset-salt",
    "LOGIN_SALT": "login-salt",
    "CHANGE_SALT": "change-salt",
    "REMEMBER_SALT": "remember-salt",
    "DEFAULT_REMEMBER_ME": False,
    "DEFAULT_HTTP_AUTH_REALM": _("Login Required"),
    "EMAIL_SUBJECT_REGISTER": _("Welcome"),
    "EMAIL_SUBJECT_CONFIRM": _("Please confirm your email"),
    "EMAIL_SUBJECT_PASSWORDLESS": _("Login instructions"),
    "EMAIL_SUBJECT_PASSWORD_NOTICE": _("Your password has been reset"),
    "EMAIL_SUBJECT_PASSWORD_CHANGE_NOTICE": _("Your password has been changed"),
    "EMAIL_SUBJECT_PASSWORD_RESET": _("Password reset instructions"),
    "EMAIL_PLAINTEXT": True,
    "EMAIL_HTML": True,
    "EMAIL_SUBJECT_TWO_FACTOR": _("Two-factor Login"),
    "EMAIL_SUBJECT_TWO_FACTOR_RESCUE": _("Two-factor Rescue"),
    "USER_IDENTITY_ATTRIBUTES": ["email"],
    "USER_IDENTITY_MAPPINGS": [
        {"email": uia_email_mapper},
        {"us_phone_number": uia_phone_mapper},
    ],
    "PHONE_REGION_DEFAULT": "US",
    "FRESHNESS": timedelta(hours=24),
    "FRESHNESS_GRACE_PERIOD": timedelta(hours=1),
    "HASHING_SCHEMES": ["sha256_crypt", "hex_md5"],
    "DEPRECATED_HASHING_SCHEMES": ["hex_md5"],
    "DATETIME_FACTORY": datetime.utcnow,
    "USE_VERIFY_PASSWORD_CACHE": False,
    "VERIFY_HASH_CACHE_TTL": 60 * 5,
    "VERIFY_HASH_CACHE_MAX_SIZE": 500,
    "TOTP_SECRETS": None,
    "TOTP_ISSUER": None,
    "SMS_SERVICE": "Dummy",
    "SMS_SERVICE_CONFIG": {
        "ACCOUNT_SID": None,
        "AUTH_TOKEN": None,
        "PHONE_NUMBER": None,
    },
    "TWO_FACTOR_REQUIRED": False,
    "TWO_FACTOR_SECRET": None,  # Deprecated - use TOTP_SECRETS
    "TWO_FACTOR_ENABLED_METHODS": ["email", "authenticator", "sms"],
    "TWO_FACTOR_URI_SERVICE_NAME": "service_name",  # Deprecated - use TOTP_ISSUER
    "TWO_FACTOR_SMS_SERVICE": "Dummy",  # Deprecated - use SMS_SERVICE
    "TWO_FACTOR_SMS_SERVICE_CONFIG": {  # Deprecated - use SMS_SERVICE_CONFIG
        "ACCOUNT_SID": None,
        "AUTH_TOKEN": None,
        "PHONE_NUMBER": None,
    },
    "UNIFIED_SIGNIN": False,
    "US_SETUP_SALT": "us-setup-salt",
    "US_SIGNIN_URL": "/us-signin",
    "US_SIGNIN_SEND_CODE_URL": "/us-signin/send-code",
    "US_SETUP_URL": "/us-setup",
    "US_VERIFY_URL": "/us-verify",
    "US_VERIFY_SEND_CODE_URL": "/us-verify/send-code",
    "US_VERIFY_LINK_URL": "/us-verify-link",
    "US_QRCODE_URL": "/us-qrcode",
    "US_POST_SETUP_VIEW": None,
    "US_SIGNIN_TEMPLATE": "security/us_signin.html",
    "US_SETUP_TEMPLATE": "security/us_setup.html",
    "US_VERIFY_TEMPLATE": "security/us_verify.html",
    "US_ENABLED_METHODS": ["password", "email", "authenticator", "sms"],
    "US_MFA_REQUIRED": ["password", "email"],
    "US_TOKEN_VALIDITY": 120,
    "US_EMAIL_SUBJECT": _("Verification Code"),
    "US_SETUP_WITHIN": "30 minutes",
    "US_SIGNIN_REPLACES_LOGIN": False,
    "CSRF_PROTECT_MECHANISMS": AUTHN_MECHANISMS,
    "CSRF_IGNORE_UNAUTH_ENDPOINTS": False,
    "CSRF_COOKIE": {"key": None},
    "CSRF_HEADER": "X-XSRF-Token",
    "CSRF_COOKIE_REFRESH_EACH_REQUEST": False,
    "BACKWARDS_COMPAT_UNAUTHN": False,
    "BACKWARDS_COMPAT_AUTH_TOKEN": False,
    "BACKWARDS_COMPAT_AUTH_TOKEN_INVALIDATE": False,
    "JOIN_USER_ROLES": True,
}

#: Default Flask-Security messages
_default_messages = {
    "API_ERROR": (_("Input not appropriate for requested API"), "error"),
    "UNAUTHORIZED": (_("You do not have permission to view this resource."), "error"),
    "UNAUTHENTICATED": (
        _("You are not authenticated. Please supply the correct credentials."),
        "error",
    ),
    "REAUTHENTICATION_REQUIRED": (
        _("You must re-authenticate to access this endpoint"),
        "error",
    ),
    "CONFIRM_REGISTRATION": (
        _("Thank you. Confirmation instructions have been sent to %(email)s."),
        "success",
    ),
    "EMAIL_CONFIRMED": (_("Thank you. Your email has been confirmed."), "success"),
    "ALREADY_CONFIRMED": (_("Your email has already been confirmed."), "info"),
    "INVALID_CONFIRMATION_TOKEN": (_("Invalid confirmation token."), "error"),
    "EMAIL_ALREADY_ASSOCIATED": (
        _("%(email)s is already associated with an account."),
        "error",
    ),
    "PASSWORD_MISMATCH": (_("Password does not match"), "error"),
    "RETYPE_PASSWORD_MISMATCH": (_("Passwords do not match"), "error"),
    "INVALID_REDIRECT": (_("Redirections outside the domain are forbidden"), "error"),
    "PASSWORD_RESET_REQUEST": (
        _("Instructions to reset your password have been sent to %(email)s."),
        "info",
    ),
    "PASSWORD_RESET_EXPIRED": (
        _(
            "You did not reset your password within %(within)s. "
            "New instructions have been sent to %(email)s."
        ),
        "error",
    ),
    "INVALID_RESET_PASSWORD_TOKEN": (_("Invalid reset password token."), "error"),
    "CONFIRMATION_REQUIRED": (_("Email requires confirmation."), "error"),
    "CONFIRMATION_REQUEST": (
        _("Confirmation instructions have been sent to %(email)s."),
        "info",
    ),
    "CONFIRMATION_EXPIRED": (
        _(
            "You did not confirm your email within %(within)s. "
            "New instructions to confirm your email have been sent "
            "to %(email)s."
        ),
        "error",
    ),
    "LOGIN_EXPIRED": (
        _(
            "You did not login within %(within)s. New instructions to login "
            "have been sent to %(email)s."
        ),
        "error",
    ),
    "LOGIN_EMAIL_SENT": (
        _("Instructions to login have been sent to %(email)s."),
        "success",
    ),
    "INVALID_LOGIN_TOKEN": (_("Invalid login token."), "error"),
    "DISABLED_ACCOUNT": (_("Account is disabled."), "error"),
    "EMAIL_NOT_PROVIDED": (_("Email not provided"), "error"),
    "INVALID_EMAIL_ADDRESS": (_("Invalid email address"), "error"),
    "INVALID_CODE": (_("Invalid code"), "error"),
    "PASSWORD_NOT_PROVIDED": (_("Password not provided"), "error"),
    "PASSWORD_NOT_SET": (_("No password is set for this user"), "error"),
    "PASSWORD_INVALID_LENGTH": (
        _("Password must be at least %(length)s characters"),
        "error",
    ),
    "PASSWORD_TOO_SIMPLE": (_("Password not complex enough"), "error"),
    "PASSWORD_BREACHED": (_("Password on breached list"), "error"),
    "PASSWORD_BREACHED_SITE_ERROR": (
        _("Failed to contact breached passwords site"),
        "error",
    ),
    "PHONE_INVALID": (_("Phone number not valid e.g. missing country code"), "error"),
    "USER_DOES_NOT_EXIST": (_("Specified user does not exist"), "error"),
    "INVALID_PASSWORD": (_("Invalid password"), "error"),
    "INVALID_PASSWORD_CODE": (_("Password or code submitted is not valid"), "error"),
    "PASSWORDLESS_LOGIN_SUCCESSFUL": (_("You have successfully logged in."), "success"),
    "FORGOT_PASSWORD": (_("Forgot password?"), "info"),
    "PASSWORD_RESET": (
        _(
            "You successfully reset your password and you have been logged in "
            "automatically."
        ),
        "success",
    ),
    "PASSWORD_IS_THE_SAME": (
        _("Your new password must be different than your previous password."),
        "error",
    ),
    "PASSWORD_CHANGE": (_("You successfully changed your password."), "success"),
    "LOGIN": (_("Please log in to access this page."), "info"),
    "REFRESH": (_("Please reauthenticate to access this page."), "info"),
    "REAUTHENTICATION_SUCCESSFUL": (_("Reauthentication successful"), "info"),
    "ANONYMOUS_USER_REQUIRED": (
        _("You can only access this endpoint when not logged in."),
        "error",
    ),
    "FAILED_TO_SEND_CODE": (_("Failed to send code. Please try again later"), "error"),
    "TWO_FACTOR_INVALID_TOKEN": (_("Invalid Token"), "error"),
    "TWO_FACTOR_LOGIN_SUCCESSFUL": (_("Your token has been confirmed"), "success"),
    "TWO_FACTOR_CHANGE_METHOD_SUCCESSFUL": (
        _("You successfully changed your two-factor method."),
        "success",
    ),
    "TWO_FACTOR_PASSWORD_CONFIRMATION_DONE": (
        _("You successfully confirmed password"),
        "success",
    ),
    "TWO_FACTOR_PASSWORD_CONFIRMATION_NEEDED": (
        _("Password confirmation is needed in order to access page"),
        "error",
    ),
    "TWO_FACTOR_PERMISSION_DENIED": (
        _("You currently do not have permissions to access this page"),
        "error",
    ),
    "TWO_FACTOR_METHOD_NOT_AVAILABLE": (_("Marked method is not valid"), "error"),
    "TWO_FACTOR_DISABLED": (
        _("You successfully disabled two factor authorization."),
        "success",
    ),
    "US_METHOD_NOT_AVAILABLE": (_("Requested method is not valid"), "error"),
    "US_SETUP_EXPIRED": (
        _("Setup must be completed within %(within)s. Please start over."),
        "error",
    ),
    "US_SETUP_SUCCESSFUL": (_("Unified sign in setup successful"), "info"),
    "US_SPECIFY_IDENTITY": (_("You must specify a valid identity to sign in"), "error"),
    "USE_CODE": (_("Use this code to sign in: %(code)s."), "info"),
}

_default_forms = {
    "login_form": LoginForm,
    "verify_form": VerifyForm,
    "confirm_register_form": ConfirmRegisterForm,
    "register_form": RegisterForm,
    "forgot_password_form": ForgotPasswordForm,
    "reset_password_form": ResetPasswordForm,
    "change_password_form": ChangePasswordForm,
    "send_confirmation_form": SendConfirmationForm,
    "passwordless_login_form": PasswordlessLoginForm,
    "two_factor_verify_code_form": TwoFactorVerifyCodeForm,
    "two_factor_setup_form": TwoFactorSetupForm,
    "two_factor_verify_password_form": TwoFactorVerifyPasswordForm,
    "two_factor_rescue_form": TwoFactorRescueForm,
    "us_signin_form": UnifiedSigninForm,
    "us_setup_form": UnifiedSigninSetupForm,
    "us_setup_validate_form": UnifiedSigninSetupValidateForm,
    "us_verify_form": UnifiedVerifyForm,
}


def _user_loader(user_id):
    """ Try to load based on fs_uniquifier (alternative_id) if available.

    Note that we don't try, and fall back to the other - primarily because some DBs
    and drivers (psycopg2) really really hate getting mismatched types during queries.
    They hate it enough that they abort the 'transaction' and refuse to do anything
    in the future until the transaction is rolled-back. But we don't really control
    that and there doesn't seem to be any way to catch the actual offensive query -
    just next time and forever, things fail.
    This assumes that if the app has fs_uniquifier, it is non-nullable as we specify
    so we use that and only that.
    """
    if hasattr(_datastore.user_model, "fs_uniquifier"):
        selector = dict(fs_uniquifier=str(user_id))
    else:
        selector = dict(id=user_id)
    user = _security.datastore.find_user(**selector)
    if user and user.active:
        return user
    return None


def _request_loader(request):
    # Short-circuit if we have already been called and verified.
    # This can happen since Flask-Login will call us (if no session) and our own
    # decorator @auth_token_required can call us.
    # N.B. we don't call current_user here since that in fact might try and LOAD
    # a user - which would call us again.
    if all(hasattr(_request_ctx_stack.top, k) for k in ["fs_authn_via", "user"]):
        if _request_ctx_stack.top.fs_authn_via == "token":
            return _request_ctx_stack.top.user

    header_key = _security.token_authentication_header
    args_key = _security.token_authentication_key
    header_token = request.headers.get(header_key, None)
    token = request.args.get(args_key, header_token)
    if request.is_json:
        data = request.get_json(silent=True) or {}
        if isinstance(data, dict):
            token = data.get(args_key, token)

    use_cache = cv("USE_VERIFY_PASSWORD_CACHE")

    try:
        data = _security.remember_token_serializer.loads(
            token, max_age=_security.token_max_age
        )
        user = _security.datastore.find_user(id=data[0])
        if not user.active:
            user = None
    except Exception:
        user = None

    if not user:
        return _security.login_manager.anonymous_user()
    if use_cache:
        cache = getattr(local_cache, "verify_hash_cache", None)
        if cache is None:
            cache = VerifyHashCache()
            local_cache.verify_hash_cache = cache
        if cache.has_verify_hash_cache(user):
            _request_ctx_stack.top.fs_authn_via = "token"
            return user
        if user.verify_auth_token(data):
            _request_ctx_stack.top.fs_authn_via = "token"
            cache.set_cache(user)
            return user
    else:
        if user.verify_auth_token(data):
            _request_ctx_stack.top.fs_authn_via = "token"
            return user

    return _security.login_manager.anonymous_user()


def _identity_loader():
    if not isinstance(current_user._get_current_object(), AnonymousUserMixin):
        identity = Identity(current_user.id)
        return identity


def _on_identity_loaded(sender, identity):
    if hasattr(current_user, "id"):
        identity.provides.add(UserNeed(current_user.id))

    for role in getattr(current_user, "roles", []):
        identity.provides.add(RoleNeed(role.name))
        for fsperm in role.get_permissions():
            identity.provides.add(FsPermNeed(fsperm))

    identity.user = current_user


def _get_login_manager(app, anonymous_user):
    lm = LoginManager()
    lm.anonymous_user = anonymous_user or AnonymousUser
    lm.localize_callback = localize_callback
    lm.login_view = "%s.login" % cv("BLUEPRINT_NAME", app=app)
    lm.user_loader(_user_loader)
    lm.request_loader(_request_loader)

    if cv("FLASH_MESSAGES", app=app):
        lm.login_message, lm.login_message_category = cv("MSG_LOGIN", app=app)
        lm.needs_refresh_message, lm.needs_refresh_message_category = cv(
            "MSG_REFRESH", app=app
        )
    else:
        lm.login_message = None
        lm.needs_refresh_message = None

    lm.init_app(app)
    return lm


def _get_principal(app):
    p = Principal(app, use_sessions=False)
    p.identity_loader(_identity_loader)
    return p


def _get_pwd_context(app):
    pw_hash = cv("PASSWORD_HASH", app=app)
    schemes = cv("PASSWORD_SCHEMES", app=app)
    deprecated = cv("DEPRECATED_PASSWORD_SCHEMES", app=app)
    if pw_hash not in schemes:
        allowed = ", ".join(schemes[:-1]) + " and " + schemes[-1]
        raise ValueError(
            "Invalid password hashing scheme %r. Allowed values are %s"
            % (pw_hash, allowed)
        )
    cc = CryptContext(
        schemes=schemes,
        default=pw_hash,
        deprecated=deprecated,
        **cv("PASSWORD_HASH_PASSLIB_OPTIONS", app=app)
    )
    return cc


def _get_i18n_domain(app):
    return Domain(
        dirname=cv("I18N_DIRNAME", app=app), domain=cv("I18N_DOMAIN", app=app)
    )


def _get_hashing_context(app):
    schemes = cv("HASHING_SCHEMES", app=app)
    deprecated = cv("DEPRECATED_HASHING_SCHEMES", app=app)
    return CryptContext(schemes=schemes, deprecated=deprecated)


def _get_serializer(app, name):
    secret_key = app.config.get("SECRET_KEY")
    salt = app.config.get("SECURITY_%s_SALT" % name.upper())
    return URLSafeTimedSerializer(secret_key=secret_key, salt=salt)


def _get_state(app, datastore, anonymous_user=None, **kwargs):
    for key, value in get_config(app).items():
        kwargs[key.lower()] = value

    kwargs.update(
        dict(
            app=app,
            datastore=datastore,
            principal=_get_principal(app),
            pwd_context=_get_pwd_context(app),
            hashing_context=_get_hashing_context(app),
            i18n_domain=_get_i18n_domain(app),
            remember_token_serializer=_get_serializer(app, "remember"),
            login_serializer=_get_serializer(app, "login"),
            reset_serializer=_get_serializer(app, "reset"),
            confirm_serializer=_get_serializer(app, "confirm"),
            us_setup_serializer=_get_serializer(app, "us_setup"),
            _context_processors={},
            _send_mail_task=None,
            _send_mail=kwargs.get("send_mail", send_mail),
            _unauthorized_callback=None,
            _render_json=default_render_json,
            _want_json=default_want_json,
            _unauthn_handler=default_unauthn_handler,
            _reauthn_handler=default_reauthn_handler,
            _unauthz_handler=default_unauthz_handler,
            _password_validator=default_password_validator,
        )
    )

    if "login_manager" not in kwargs:
        kwargs["login_manager"] = _get_login_manager(app, anonymous_user)

    for key, value in _default_forms.items():
        if key not in kwargs or not kwargs[key]:
            kwargs[key] = value

    return _SecurityState(**kwargs)


def _context_processor():
    return dict(url_for_security=url_for_security, security=_security)


class RoleMixin(object):
    """Mixin for `Role` model definitions"""

    def __eq__(self, other):
        return self.name == other or self.name == getattr(other, "name", None)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.name)

    def get_permissions(self):
        """
        Return set of permissions associated with role.

        Either takes a comma separated string of permissions or
        an interable of strings if permissions are in their own
        table.

        .. versionadded:: 3.3.0
        """
        if hasattr(self, "permissions") and self.permissions:
            if isinstance(self.permissions, set):
                return self.permissions
            elif isinstance(self.permissions, list):
                return set(self.permissions)
            else:
                # Assume this is a comma separated list
                return set(self.permissions.split(","))
        return set([])

    def add_permissions(self, permissions):
        """
        Add one or more permissions to role.

        :param permissions: a set, list, or single string.

        Caller must commit to DB.

        .. versionadded:: 3.3.0

        .. deprecated:: 3.4.4
            Use :meth:`.UserDatastore.remove_permissions_from_role`
        """
        if hasattr(self, "permissions"):
            current_perms = self.get_permissions()
            if isinstance(permissions, set):
                perms = permissions
            elif isinstance(permissions, list):
                perms = set(permissions)
            else:
                perms = {permissions}
            self.permissions = ",".join(current_perms.union(perms))
        else:  # pragma: no cover
            raise NotImplementedError("Role model doesn't have permissions")

    def remove_permissions(self, permissions):
        """
        Remove one or more permissions from role.

        :param permissions: a set, list, or single string.

        Caller must commit to DB.

        .. versionadded:: 3.3.0

        .. deprecated:: 3.4.4
            Use :meth:`.UserDatastore.remove_permissions_from_role`
        """
        if hasattr(self, "permissions"):
            current_perms = self.get_permissions()
            if isinstance(permissions, set):
                perms = permissions
            elif isinstance(permissions, list):
                perms = set(permissions)
            else:
                perms = {permissions}
            self.permissions = ",".join(current_perms.difference(perms))
        else:  # pragma: no cover
            raise NotImplementedError("Role model doesn't have permissions")


class UserMixin(BaseUserMixin):
    """Mixin for `User` model definitions"""

    def get_id(self):
        """Returns the user identification attribute.

        This will be `fs_uniquifier` if that is available, else base class id
        (which is via Flask-Login and is user.id).

        .. versionadded:: 3.4.0
        """
        if hasattr(self, "fs_uniquifier") and self.fs_uniquifier is not None:
            # Use fs_uniquifier as alternative_id if available and not None
            alternative_id = str(self.fs_uniquifier)
            if len(alternative_id) > 0:
                # Return only if alternative_id is a valid value
                return alternative_id

        # Use upstream value if alternative_id is unavailable
        return BaseUserMixin.get_id(self)

    @property
    def is_active(self):
        """Returns `True` if the user is active."""
        return self.active

    def get_auth_token(self):
        """Constructs the user's authentication token.

        This data MUST be securely signed using the ``remember_token_serializer``
        """
        data = [str(self.id), hash_data(self.password)]
        if hasattr(self, "fs_uniquifier"):
            data.append(self.fs_uniquifier)
        return _security.remember_token_serializer.dumps(data)

    def verify_auth_token(self, data):
        """
        Perform additional verification of contents of auth token.
        Prior to this being called the token has been validated (via signing)
        and has not expired.

        :param data: the data as formulated by :meth:`get_auth_token`

        .. versionadded:: 3.3.0
        """
        if len(data) > 2 and hasattr(self, "fs_uniquifier"):
            # has uniquifier - use that
            if data[2] == self.fs_uniquifier:
                return True
            # Don't even try old way - if they have defined a uniquifier
            # we want that to be able to invalidate tokens if changed.
            return False
        # Fall back to old and very expensive check
        if verify_hash(data[1], self.password):
            return True
        return False

    def has_role(self, role):
        """Returns `True` if the user identifies with the specified role.

        :param role: A role name or `Role` instance"""
        if isinstance(role, string_types):
            return role in (role.name for role in self.roles)
        else:
            return role in self.roles

    def has_permission(self, permission):
        """
        Returns `True` if user has this permission (via a role it has).

        :param permission: permission string name

        .. versionadded:: 3.3.0

        """
        for role in self.roles:
            if permission in role.get_permissions():
                return True
        return False

    def get_security_payload(self):
        """Serialize user object as response payload."""
        return {"id": str(self.id)}

    def get_redirect_qparams(self, existing=None):
        """Return user info that will be added to redirect query params.

        :param existing: A dict that will be updated.
        :return: A dict whose keys will be query params and values will be query values.

        .. versionadded:: 3.2.0
        """
        if not existing:
            existing = {}
        existing.update({"email": self.email})
        return existing

    def verify_and_update_password(self, password):
        """Returns ``True`` if the password is valid for the specified user.

        Additionally, the hashed password in the database is updated if the
        hashing algorithm happens to have changed.

        N.B. you MUST call DB commit if you are using a session-based datastore
        (such as SqlAlchemy) since the user instance might have been altered
        (i.e. ``app.security.datastore.commit()``).
        This is usually handled in the view.

        :param password: A plaintext password to verify

        .. versionadded:: 3.2.0
        """
        return verify_and_update_password(password, self)

    def calc_username(self):
        """ Come up with the best 'username' based on how the app
        is configured (via :py:data:`SECURITY_USER_IDENTITY_ATTRIBUTES`).
        Returns the first non-null match (and converts to string).
        In theory this should NEVER be the empty string unless the user
        record isn't actually valid.

        .. versionadded:: 3.4.0
        """
        cusername = None
        for attr in get_identity_attributes():
            cusername = getattr(self, attr, None)
            if cusername is not None and len(str(cusername)) > 0:
                break
        return str(cusername) if cusername is not None else ""

    def us_send_security_token(self, method, **kwargs):
        """ Generate and send the security code for unified sign in.

        :param method: The method in which the code will be sent
        :param kwargs: Opaque parameters that are subject to change at any time
        :return: None if successful, error message if not.

        This is a wrapper around :meth:`us_send_security_token`
        that can be overridden to manage any errors.

        .. versionadded:: 3.4.0
        """
        try:
            us_send_security_token(self, method, **kwargs)
        except Exception:
            return get_message("FAILED_TO_SEND_CODE")[0]
        return None

    def tf_send_security_token(self, method, **kwargs):
        """ Generate and send the security code for two-factor.

        :param method: The method in which the code will be sent
        :param kwargs: Opaque parameters that are subject to change at any time
        :return: None if successful, error message if not.

        This is a wrapper around :meth:`tf_send_security_token`
        that can be overridden to manage any errors.

        .. versionadded:: 3.4.0
        """
        try:
            tf_send_security_token(self, method, **kwargs)
        except Exception:
            return get_message("FAILED_TO_SEND_CODE")[0]
        return None


class AnonymousUser(AnonymousUserMixin):
    """AnonymousUser definition"""

    def __init__(self):
        self.roles = ImmutableList()

    def has_role(self, *args):
        """Returns `False`"""
        return False


class _SecurityState(object):
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key.lower(), value)

    def _add_ctx_processor(self, endpoint, fn):
        group = self._context_processors.setdefault(endpoint, [])
        fn not in group and group.append(fn)

    def _run_ctx_processor(self, endpoint):
        rv = {}
        for g in [None, endpoint]:
            for fn in self._context_processors.setdefault(g, []):
                rv.update(fn())
        return rv

    def context_processor(self, fn):
        self._add_ctx_processor(None, fn)

    def forgot_password_context_processor(self, fn):
        self._add_ctx_processor("forgot_password", fn)

    def login_context_processor(self, fn):
        self._add_ctx_processor("login", fn)

    def register_context_processor(self, fn):
        self._add_ctx_processor("register", fn)

    def reset_password_context_processor(self, fn):
        self._add_ctx_processor("reset_password", fn)

    def change_password_context_processor(self, fn):
        self._add_ctx_processor("change_password", fn)

    def send_confirmation_context_processor(self, fn):
        self._add_ctx_processor("send_confirmation", fn)

    def send_login_context_processor(self, fn):
        self._add_ctx_processor("send_login", fn)

    def verify_context_processor(self, fn):
        self._add_ctx_processor("verify", fn)

    def mail_context_processor(self, fn):
        self._add_ctx_processor("mail", fn)

    def tf_verify_password_context_processor(self, fn):
        self._add_ctx_processor("tf_verify_password", fn)

    def tf_setup_context_processor(self, fn):
        self._add_ctx_processor("tf_setup", fn)

    def tf_token_validation_context_processor(self, fn):
        self._add_ctx_processor("tf_token_validation", fn)

    def us_signin_context_processor(self, fn):
        self._add_ctx_processor("us_signin", fn)

    def us_setup_context_processor(self, fn):
        self._add_ctx_processor("us_setup", fn)

    def us_verify_context_processor(self, fn):
        self._add_ctx_processor("us_verify", fn)

    def send_mail_task(self, fn):
        self._send_mail_task = fn

    def send_mail(self, fn):
        self._send_mail = fn

    def unauthorized_handler(self, fn):
        warnings.warn(
            "'unauthorized_handler' has been replaced with"
            " 'unauthz_handler' and 'unauthn_handler'",
            DeprecationWarning,
        )
        self._unauthorized_callback = fn

    def totp_factory(self, tf):
        self._totp_factory = tf

    def render_json(self, fn):
        self._render_json = fn

    def want_json(self, fn):
        self._want_json = fn

    def unauthz_handler(self, cb):
        self._unauthz_handler = cb

    def unauthn_handler(self, cb):
        self._unauthn_handler = cb

    def reauthn_handler(self, cb):
        self._reauthn_handler = cb

    def password_validator(self, cb):
        self._password_validator = cb


class Security(object):
    """The :class:`Security` class initializes the Flask-Security extension.

    :param app: The application.
    :param datastore: An instance of a user datastore.
    :param register_blueprint: to register the Security blueprint or not.
    :param login_form: set form for the login view
    :param verify_form: set form for re-authentication due to freshness check
    :param register_form: set form for the register view when
            *SECURITY_CONFIRMABLE* is false
    :param confirm_register_form: set form for the register view when
            *SECURITY_CONFIRMABLE* is true
    :param forgot_password_form: set form for the forgot password view
    :param reset_password_form: set form for the reset password view
    :param change_password_form: set form for the change password view
    :param send_confirmation_form: set form for the send confirmation view
    :param passwordless_login_form: set form for the passwordless login view
    :param two_factor_setup_form: set form for the 2FA setup view
    :param two_factor_verify_code_form: set form the the 2FA verify code view
    :param two_factor_rescue_form: set form for the 2FA rescue view
    :param two_factor_verify_password_form: set form for the 2FA verify password view
    :param us_signin_form: set form for the unified sign in view
    :param us_setup_form: set form for the unified sign in setup view
    :param us_setup_validate_form: set form for the unified sign in setup validate view
    :param us_verify_form: set form for re-authenticating due to freshness check
    :param anonymous_user: class to use for anonymous user
    :param render_template: function to use to render templates. The default is Flask's
     render_template() function.
    :param send_mail: function to use to send email. Defaults to :func:`send_mail`
    :param json_encoder_cls: Class to use as blueprint.json_encoder.
     Defaults to :class:`FsJsonEncoder`
    :param totp_cls: Class to use as TOTP factory. Defaults to :class:`Totp`
    :param phone_util_cls: Class to use for phone number utilities.
     Defaults to :class:`PhoneUtil`

    .. versionadded:: 3.4.0
        ``verify_form`` added as part of freshness/re-authentication

    .. versionadded:: 3.4.0
        ``us_signin_form``, ``us_setup_form``, ``us_setup_validate_form``, and
        ``us_verify_form`` added as part of the :ref:`unified-sign-in` feature.

    .. versionadded:: 3.4.0
        ``totp_cls`` added to enable applications to implement replay protection - see
        :py:class:`Totp`.

    .. versionadded:: 3.4.0
        ``phone_util_cls`` added to allow different phone number
         parsing implementations - see :py:class:`PhoneUtil`
    """

    def __init__(self, app=None, datastore=None, register_blueprint=True, **kwargs):

        self.app = app
        self._datastore = datastore
        self._register_blueprint = register_blueprint
        self._kwargs = kwargs

        self._state = None  # set by init_app
        if app is not None and datastore is not None:
            self._state = self.init_app(
                app, datastore, register_blueprint=register_blueprint, **kwargs
            )

    def init_app(self, app, datastore=None, register_blueprint=None, **kwargs):
        """Initializes the Flask-Security extension for the specified
        application and datastore implementation.

        :param app: The application.
        :param datastore: An instance of a user datastore.
        :param register_blueprint: to register the Security blueprint or not.
        """
        self.app = app

        if datastore is None:
            datastore = self._datastore

        if register_blueprint is None:
            register_blueprint = self._register_blueprint

        for key, value in self._kwargs.items():
            kwargs.setdefault(key, value)

        if "render_template" not in kwargs:
            kwargs.setdefault("render_template", self.render_template)
        if "json_encoder_cls" not in kwargs:
            kwargs.setdefault("json_encoder_cls", FsJsonEncoder)
        if "totp_cls" not in kwargs:
            kwargs.setdefault("totp_cls", Totp)
        if "phone_util_cls" not in kwargs:
            kwargs.setdefault("phone_util_cls", PhoneUtil)

        for key, value in _default_config.items():
            app.config.setdefault("SECURITY_" + key, value)

        for key, value in _default_messages.items():
            app.config.setdefault("SECURITY_MSG_" + key, value)

        identity_loaded.connect_via(app)(_on_identity_loaded)

        self._state = state = _get_state(app, datastore, **kwargs)

        if register_blueprint:
            bp = create_blueprint(
                app, state, __name__, json_encoder=kwargs["json_encoder_cls"]
            )
            app.register_blueprint(bp)
            app.context_processor(_context_processor)

        @app.before_first_request
        def _register_i18n():
            # N.B. as of jinja 2.9 '_' is always registered
            # http://jinja.pocoo.org/docs/2.10/extensions/#i18n-extension
            if "_" not in app.jinja_env.globals:
                current_app.jinja_env.globals["_"] = state.i18n_domain.gettext
            # Register so other packages can reference our translations.
            current_app.jinja_env.globals["_fsdomain"] = state.i18n_domain.gettext

        @app.before_first_request
        def _csrf_init():
            # various config checks - some of these are opinionated in that there
            # could be a reason for some of these combinations - but in general
            # they cause strange behavior.
            # WTF_CSRF_ENABLED defaults to True if not set in Flask-WTF
            if not current_app.config.get("WTF_CSRF_ENABLED", True):
                return
            csrf = current_app.extensions.get("csrf", None)

            # If they don't want ALL mechanisms protected, then they must
            # set WTF_CSRF_CHECK_DEFAULT=False so that our decorators get control.
            if cv("CSRF_PROTECT_MECHANISMS") != AUTHN_MECHANISMS:
                if not csrf:
                    # This isn't good.
                    raise ValueError(
                        "CSRF_PROTECT_MECHANISMS defined but"
                        " CsrfProtect not part of application"
                    )
                if current_app.config.get("WTF_CSRF_CHECK_DEFAULT", True):
                    raise ValueError(
                        "WTF_CSRF_CHECK_DEFAULT must be set to False if"
                        " CSRF_PROTECT_MECHANISMS is set"
                    )
            # We don't get control unless they turn off WTF_CSRF_CHECK_DEFAULT if
            # they have enabled global CSRFProtect.
            if (
                cv("CSRF_IGNORE_UNAUTH_ENDPOINTS")
                and csrf
                and current_app.config.get("WTF_CSRF_CHECK_DEFAULT", False)
            ):
                raise ValueError(
                    "To ignore unauth endpoints you must set WTF_CSRF_CHECK_DEFAULT"
                    " to False"
                )

            csrf_cookie = cv("CSRF_COOKIE")
            if csrf_cookie and csrf_cookie["key"] and not csrf:
                # Common use case is for cookie value to be used as contents for header
                # which is only looked at when CsrfProtect is initialized.
                # Yes, this is opinionated - they can always get CSRF token via:
                # 'get /login'
                raise ValueError(
                    "CSRF_COOKIE defined however CsrfProtect not part of application"
                )

            if csrf:
                csrf.exempt("flask_security.views.logout")
            if csrf_cookie and csrf_cookie["key"]:
                current_app.after_request(csrf_cookie_handler)
                # Add configured header to WTF_CSRF_HEADERS
                current_app.config["WTF_CSRF_HEADERS"].append(cv("CSRF_HEADER"))

        @app.before_first_request
        def _init_phone_util():
            state._phone_util = state.phone_util_cls()

        app.extensions["security"] = state

        if hasattr(app, "cli"):
            from .cli import users, roles

            if state.cli_users_name:
                app.cli.add_command(users, state.cli_users_name)
            if state.cli_roles_name:
                app.cli.add_command(roles, state.cli_roles_name)

        # Migrate from TWO_FACTOR config to generic config.
        for newc, oldc in [
            ("SECURITY_SMS_SERVICE", "SECURITY_TWO_FACTOR_SMS_SERVICE"),
            ("SECURITY_SMS_SERVICE_CONFIG", "SECURITY_TWO_FACTOR_SMS_SERVICE_CONFIG"),
            ("SECURITY_TOTP_SECRETS", "SECURITY_TWO_FACTOR_SECRET"),
            ("SECURITY_TOTP_ISSUER", "SECURITY_TWO_FACTOR_URI_SERVICE_NAME"),
        ]:
            if not app.config.get(newc, None):
                app.config[newc] = app.config.get(oldc, None)

        # Two factor configuration checks and setup
        multi_factor = False
        if cv("UNIFIED_SIGNIN", app=app):
            multi_factor = True
            if len(cv("US_ENABLED_METHODS", app=app)) < 1:
                raise ValueError("Must configure some US_ENABLED_METHODS")
        if cv("TWO_FACTOR", app=app):
            multi_factor = True
            if len(cv("TWO_FACTOR_ENABLED_METHODS", app=app)) < 1:
                raise ValueError("Must configure some TWO_FACTOR_ENABLED_METHODS")

        if multi_factor:
            self._check_modules("pyqrcode", "TWO_FACTOR or UNIFIED_SIGNIN")
            self._check_modules("cryptography", "TWO_FACTOR or UNIFIED_SIGNIN")

            need_sms = (
                cv("UNIFIED_SIGNIN", app=app)
                and "sms" in cv("US_ENABLED_METHODS", app=app)
            ) or (
                cv("TWO_FACTOR", app=app)
                and "sms" in cv("TWO_FACTOR_ENABLED_METHODS", app=app)
            )
            if need_sms:
                sms_service = cv("SMS_SERVICE", app=app)
                if sms_service == "Twilio":  # pragma: no cover
                    self._check_modules("twilio", "SMS")
                if state.phone_util_cls == PhoneUtil:
                    self._check_modules("phonenumbers", "SMS")

            secrets = cv("TOTP_SECRETS", app=app)
            issuer = cv("TOTP_ISSUER", app=app)
            if not secrets or not issuer:
                raise ValueError("Both TOTP_SECRETS and TOTP_ISSUER must be set")
            state.totp_factory(state.totp_cls(secrets, issuer))

        if cv("USE_VERIFY_PASSWORD_CACHE", app=app):
            self._check_modules("cachetools", "USE_VERIFY_PASSWORD_CACHE")

        if cv("PASSWORD_COMPLEXITY_CHECKER", app=app) == "zxcvbn":
            self._check_modules("zxcvbn", "PASSWORD_COMPLEXITY_CHECKER")
        return state

    def _check_modules(self, module, config_name):  # pragma: no cover
        PY3 = sys.version_info[0] == 3
        if PY3:
            from importlib.util import find_spec

            module_exists = find_spec(module)

        else:
            import imp

            try:
                imp.find_module(module)
                module_exists = True
            except ImportError:
                module_exists = False

        if not module_exists:
            raise ValueError("{} is required for {}".format(module, config_name))

        return module_exists

    def render_template(self, *args, **kwargs):
        return render_template(*args, **kwargs)

    def send_mail(self, fn):
        """ Function used to send emails.

        :param fn: Function with signature(subject, recipient, template, context)

        See :meth:`send_mail` for details.

        .. versionadded:: 3.1.0
        """
        self._state._send_mail = fn

    def render_json(self, cb):
        """ Callback to render response payload as JSON.

        :param cb: Callback function with
         signature (payload, code, headers=None, user=None)

            :payload: A dict. Please see the formal API spec for details.
            :code: Http status code
            :headers: Headers object
            :user: the UserDatastore object (or None). Note that this is usually
                           the same as current_user - but not always.

        The default implementation simply returns::

                headers["Content-Type"] = "application/json"
                payload = dict(meta=dict(code=code), response=payload)
                return make_response(jsonify(payload), code, headers)

        .. important::
            Be aware the Flask's ``jsonify`` method will first look to see if a
            ``json_encoder`` has been set on the blueprint corresponding to the current
            request. If not then it looks for a ``json_encoder`` registered on the app;
            and finally uses Flask's default JSONEncoder class. Flask-Security registers
            :func:`FsJsonEncoder` as its blueprint json_encoder.


        This can be used by applications to unify all their JSON API responses.
        This is called in a request context and should return a Response or something
        Flask can create a Response from.

        .. versionadded:: 3.3.0
        """
        self._state._render_json = cb

    def want_json(self, fn):
        """ Function that returns True if response should be JSON (based on the request)

        :param fn: Function with the following signature (request)

            :request: Werkzueg/Flask request

        The default implementation returns True if either the Content-Type is
        "application/json" or the best Accept header value is "application/json".

        .. versionadded:: 3.3.0
        """
        self._state._want_json = fn

    def unauthz_handler(self, cb):
        """
        Callback for failed authorization.
        This is called by the :func:`roles_required`, :func:`roles_accepted`,
        :func:`permissions_required`, or :func:`permissions_accepted`
        if a role or permission is missing.

        :param cb: Callback function with signature (func, params)

            :func: the decorator function (e.g. roles_required)
            :params: list of what (if any) was passed to the decorator.

        Should return a Response or something Flask can create a Response from.
        Can raise an exception if it is handled as part of
        flask.errorhandler(<exception>)

        With the passed parameters the application could deliver a concise error
        message.

        .. versionadded:: 3.3.0
        """
        self._state._unauthz_handler = cb

    def unauthn_handler(self, cb):
        """
        Callback for failed authentication.
        This is called by :func:`auth_required`, :func:`auth_token_required`
        or :func:`http_auth_required` if authentication fails.

        :param cb: Callback function with signature (mechanisms, headers=None)

            :mechanisms: List of which authentication mechanisms were tried
            :headers: dict of headers to return

        Should return a Response or something Flask can create a Response from.
        Can raise an exception if it is handled as part of
        ``flask.errorhandler(<exception>)``

        The default implementation will return a 401 response if the request was JSON,
        otherwise lets ``flask_login.login_manager.unauthorized()`` handle redirects.

        .. versionadded:: 3.3.0
        """
        self._state._unauthn_handler = cb

    def reauthn_handler(self, cb):
        """
        Callback when endpoint required a fresh authentication.
        This is called by :func:`auth_required`.

        :param cb: Callback function with signature (within, grace)

            :within: timedelta that endpoint required fresh authentication within.
            :grace: timedelta of grace period that endpoint allowed.

        Should return a Response or something Flask can create a Response from.
        Can raise an exception if it is handled as part of
        ``flask.errorhandler(<exception>)``

        The default implementation will return a 401 response if the request was JSON,
        otherwise will redirect to :py:data:`SECURITY_US_VERIFY_URL`
        (if :py:data:`SECURITY_UNIFIED_SIGNIN` is enabled)
        else to :py:data:`SECURITY_VERIFY_URL`.
        If both of those are None it sends an ``abort(401)``.

        See :meth:`flask_security.auth_required` for details about freshness checking.

        .. versionadded:: 3.4.0
        """
        self._state._reauthn_handler = cb

    def password_validator(self, cb):
        """
        Callback for validating a user password.
        This is called on registration as well as change and reset password.
        For registration, ``kwargs`` will be all the form input fields that are
        attributes of the user model.
        For reset/change, ``kwargs`` will be user=UserModel

        :param cb: Callback function with signature (password, is_register, kwargs)

            :password: desired new plain text password
            :is_register: True if called as part of initial registration
            :kwargs: user info

        Returns: None if password passes all validations. A list of (localized) messages
        if not.

        .. versionadded:: 3.4.0
            Refer to :ref:`pass_validation_topic` for more information.
        """
        self._state._password_validator = cb

    def __getattr__(self, name):
        return getattr(self._state, name, None)
