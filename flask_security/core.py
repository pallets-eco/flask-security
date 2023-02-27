"""
    flask_security.core
    ~~~~~~~~~~~~~~~~~~~

    Flask-Security core module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2017 by CERN.
    :copyright: (c) 2017 by ETH Zurich, Swiss Data Science Center.
    :copyright: (c) 2019-2023 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from datetime import datetime, timedelta
from dataclasses import dataclass
import importlib
import re
import typing as t
import warnings

import pkg_resources
from flask import current_app, g
from flask_login import AnonymousUserMixin, LoginManager
from flask_login import UserMixin as BaseUserMixin
from flask_login import current_user
from flask_principal import Identity, Principal, RoleNeed, UserNeed, identity_loaded
from itsdangerous import URLSafeTimedSerializer
from passlib.context import CryptContext
from werkzeug.datastructures import ImmutableList
from werkzeug.local import LocalProxy

from .babel import FsDomain
from .decorators import (
    default_reauthn_handler,
    default_unauthn_handler,
    default_unauthz_handler,
)
from .forms import (
    ChangePasswordForm,
    ConfirmRegisterForm,
    ForgotPasswordForm,
    Form,
    LoginForm,
    PasswordlessLoginForm,
    RegisterForm,
    RegisterFormMixin,
    ResetPasswordForm,
    SendConfirmationForm,
    TwoFactorVerifyCodeForm,
    TwoFactorSetupForm,
    TwoFactorRescueForm,
    VerifyForm,
    get_register_username_field,
    login_username_field,
)
from .json import setup_json
from .mail_util import MailUtil
from .password_util import PasswordUtil
from .phone_util import PhoneUtil
from .oauth_glue import OAuthGlue
from .proxies import _security
from .recovery_codes import (
    MfRecoveryForm,
    MfRecoveryCodesForm,
    MfRecoveryCodesUtil,
)
from .tf_plugin import TfPlugin, TwoFactorSelectForm
from .twofactor import tf_send_security_token
from .unified_signin import (
    UnifiedSigninForm,
    UnifiedSigninSetupForm,
    UnifiedSigninSetupValidateForm,
    UnifiedVerifyForm,
    us_send_security_token,
)
from .webauthn import (
    WebAuthnDeleteForm,
    WebAuthnRegisterForm,
    WebAuthnRegisterResponseForm,
    WebAuthnSigninForm,
    WebAuthnSigninResponseForm,
    WebAuthnVerifyForm,
)
from .webauthn_util import WebauthnUtil
from .username_util import UsernameUtil
from .totp import Totp
from .utils import _
from .utils import config_value as cv
from .utils import (
    FsPermNeed,
    csrf_cookie_handler,
    default_render_template,
    default_want_json,
    get_config,
    get_identity_attribute,
    get_identity_attributes,
    get_message,
    get_request_attr,
    localize_callback,
    set_request_attr,
    uia_email_mapper,
    uia_username_mapper,
    url_for_security,
    verify_and_update_password,
)
from .views import create_blueprint, default_render_json

if t.TYPE_CHECKING:  # pragma: no cover
    import flask
    from flask import Request
    from flask.typing import ResponseValue
    import flask_login.mixins
    from authlib.integrations.flask_client import OAuth
    from .datastore import Role, User, UserDatastore


# List of authentication mechanisms supported.
AUTHN_MECHANISMS = ("basic", "session", "token")


#: Default Flask-Security configuration
_default_config: t.Dict[str, t.Any] = {
    "BLUEPRINT_NAME": "security",
    "CLI_ROLES_NAME": "roles",
    "CLI_USERS_NAME": "users",
    "URL_PREFIX": None,
    "STATIC_FOLDER": "static",
    "STATIC_FOLDER_URL": "/fs-static",
    "SUBDOMAIN": None,
    "FLASH_MESSAGES": True,
    "RETURN_GENERIC_RESPONSES": False,
    "I18N_DOMAIN": "flask_security",
    "I18N_DIRNAME": pkg_resources.resource_filename("flask_security", "translations"),
    "EMAIL_VALIDATOR_ARGS": None,
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
    "PASSWORD_NORMALIZE_FORM": "NFKD",
    "PASSWORD_REQUIRED": True,
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
    "TWO_FACTOR_RESCUE_URL": "/tf-rescue",
    "TWO_FACTOR_SELECT_URL": "/tf-select",
    "TWO_FACTOR_POST_SETUP_VIEW": ".two_factor_setup",  # endpoint or URL
    "TWO_FACTOR_ERROR_VIEW": ".login",
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
    "REQUIRES_CONFIRMATION_ERROR_VIEW": None,
    "REDIRECT_HOST": None,
    "REDIRECT_BEHAVIOR": None,
    "REDIRECT_ALLOW_SUBDOMAINS": False,
    "REDIRECT_VALIDATE_MODE": None,
    "REDIRECT_VALIDATE_RE": r"^/{4,}|\\{3,}|[\s\000-\037][/\\]{2,}",
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
    "TWO_FACTOR_SELECT_TEMPLATE": "security/two_factor_select.html",
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
    "TWO_FACTOR_ALWAYS_VALIDATE": True,
    "TWO_FACTOR_LOGIN_VALIDITY": "30 days",
    "TWO_FACTOR_VALIDITY_SALT": "tf-validity-salt",
    "TWO_FACTOR_VALIDITY_COOKIE": {
        "httponly": True,
        "secure": False,
        "samesite": "Strict",
    },
    "TWO_FACTOR_RESCUE_EMAIL": True,
    "MULTI_FACTOR_RECOVERY_CODES": False,
    "MULTI_FACTOR_RECOVERY_CODES_N": 5,
    "MULTI_FACTOR_RECOVERY_CODES_URL": "/mf-recovery-codes",
    "MULTI_FACTOR_RECOVERY_CODES_TEMPLATE": "security/mf_recovery_codes.html",
    "MULTI_FACTOR_RECOVERY_URL": "/mf-recovery",
    "MULTI_FACTOR_RECOVERY_TEMPLATE": "security/mf_recovery.html",
    "MULTI_FACTOR_RECOVERY_CODES_KEYS": None,
    "MULTI_FACTOR_RECOVERY_CODE_TTL": None,
    "OAUTH_ENABLE": False,
    "OAUTH_BUILTIN_PROVIDERS": ["github", "google"],
    "OAUTH_START_URL": "/login/oauthstart",
    "OAUTH_RESPONSE_URL": "/login/oauthresponse",
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
    "USER_IDENTITY_ATTRIBUTES": [
        {"email": {"mapper": uia_email_mapper, "case_insensitive": True}}
    ],
    "PHONE_REGION_DEFAULT": "US",
    "FRESHNESS": timedelta(hours=24),
    "FRESHNESS_GRACE_PERIOD": timedelta(hours=1),
    "API_ENABLED_METHODS": ["session", "token"],
    "HASHING_SCHEMES": ["sha256_crypt", "hex_md5"],
    "DEPRECATED_HASHING_SCHEMES": ["hex_md5"],
    "DATETIME_FACTORY": datetime.utcnow,
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
    "TWO_FACTOR_IMPLEMENTATIONS": {
        "code": "flask_security.twofactor.CodeTfPlugin",
        "webauthn": "flask_security.webauthn.WebAuthnTfPlugin",
    },
    "UNIFIED_SIGNIN": False,
    "US_SETUP_SALT": "us-setup-salt",
    "US_SIGNIN_URL": "/us-signin",
    "US_SIGNIN_SEND_CODE_URL": "/us-signin/send-code",
    "US_SETUP_URL": "/us-setup",
    "US_VERIFY_URL": "/us-verify",
    "US_VERIFY_SEND_CODE_URL": "/us-verify/send-code",
    "US_VERIFY_LINK_URL": "/us-verify-link",
    "US_POST_SETUP_VIEW": ".us_setup",  # endpoint or URL
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
    "CSRF_COOKIE_NAME": None,
    "CSRF_COOKIE": {
        "samesite": "Strict",
        "httponly": False,
        "secure": False,
    },
    "CSRF_HEADER": "X-XSRF-Token",
    "CSRF_COOKIE_REFRESH_EACH_REQUEST": False,
    "BACKWARDS_COMPAT_UNAUTHN": False,
    "BACKWARDS_COMPAT_AUTH_TOKEN": False,
    "JOIN_USER_ROLES": True,
    "USERNAME_ENABLE": False,
    "USERNAME_REQUIRED": False,
    "USERNAME_MIN_LENGTH": 4,
    "USERNAME_MAX_LENGTH": 32,
    "USERNAME_NORMALIZE_FORM": "NFKD",
    "WEBAUTHN": False,
    "WAN_CHALLENGE_BYTES": None,  # uses system default
    "WAN_POST_REGISTER_VIEW": ".wan_register",  # endpoint or URL
    "WAN_RP_NAME": "My Flask App",
    "WAN_SALT": "wan-salt",
    "WAN_REGISTER_TIMEOUT": 60000,  # milliseconds
    "WAN_REGISTER_TEMPLATE": "security/wan_register.html",
    "WAN_REGISTER_URL": "/wan-register",
    "WAN_REGISTER_WITHIN": "30 minutes",
    "WAN_SIGNIN_TIMEOUT": 60000,  # milliseconds
    "WAN_SIGNIN_TEMPLATE": "security/wan_signin.html",
    "WAN_SIGNIN_URL": "/wan-signin",
    "WAN_SIGNIN_WITHIN": "1 minutes",
    "WAN_DELETE_URL": "/wan-delete",
    "WAN_VERIFY_URL": "/wan-verify",
    "WAN_VERIFY_TEMPLATE": "security/wan_verify.html",
    "WAN_ALLOW_AS_FIRST_FACTOR": True,
    "WAN_ALLOW_AS_MULTI_FACTOR": True,
    "WAN_ALLOW_USER_HINTS": True,
    "WAN_ALLOW_AS_VERIFY": ["first", "secondary"],
    "ZXCVBN_MINIMUM_SCORE": 3,
}

#: Default Flask-Security messages
_default_messages = {
    "API_ERROR": (_("Input not appropriate for requested API"), "error"),
    "GENERIC_AUTHN_FAILED": (
        _("Authentication failed - identity or password/passcode invalid"),
        "error",
    ),
    "GENERIC_RECOVERY": (
        _(
            "If that email address is in our system, "
            "you will receive an email describing how to reset your password."
        ),
        "info",
    ),
    "GENERIC_US_SIGNIN": (
        _("If that identity is in our system, you were sent a code."),
        "info",
    ),
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
    "IDENTITY_ALREADY_ASSOCIATED": (
        _(
            "Identity attribute '%(attr)s' with value '%(value)s' is already"
            " associated with an account."
        ),
        "error",
    ),
    "IDENTITY_NOT_REGISTERED": (
        _("Identity %(id)s not registered"),
        "error",
    ),
    "OAUTH_HANDSHAKE_ERROR": (
        _(
            "An error occurred while communicating with the Oauth provider. "
            "Please try again."
        ),
        "error",
    ),
    "PASSWORD_MISMATCH": (_("Password does not match"), "error"),
    "RETYPE_PASSWORD_MISMATCH": (_("Passwords do not match"), "error"),
    "INVALID_REDIRECT": (_("Redirections outside the domain are forbidden"), "error"),
    "INVALID_RECOVERY_CODE": (_("Recovery code invalid"), "error"),
    "NO_RECOVERY_CODES_SETUP": (_("No recovery codes generated yet"), "info"),
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
    "CODE_HAS_BEEN_SENT": (_("Code has been sent."), "info"),
    "FAILED_TO_SEND_CODE": (_("Failed to send code. Please try again later"), "error"),
    "TWO_FACTOR_INVALID_TOKEN": (_("Invalid code"), "error"),
    "TWO_FACTOR_LOGIN_SUCCESSFUL": (_("Your code has been confirmed"), "success"),
    "TWO_FACTOR_CHANGE_METHOD_SUCCESSFUL": (
        _("You successfully changed your two-factor method."),
        "success",
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
    "USERNAME_INVALID_LENGTH": (
        _(
            "Username must be at least %(min)d characters and less than"
            " %(max)d characters"
        ),
        "error",
    ),
    "USERNAME_ILLEGAL_CHARACTERS": (
        _("Username contains illegal characters"),
        "error",
    ),
    "USERNAME_DISALLOWED_CHARACTERS": (
        _("Username can contain only letters and numbers"),
        "error",
    ),
    "USERNAME_NOT_PROVIDED": (_("Username not provided"), "error"),
    "USERNAME_ALREADY_ASSOCIATED": (
        _("%(username)s is already associated with an account."),
        "error",
    ),
    "WEBAUTHN_EXPIRED": (
        _("WebAuthn operation must be completed within %(within)s. Please start over."),
        "error",
    ),
    "WEBAUTHN_NAME_REQUIRED": (
        _("Nickname for new credential is required."),
        "error",
    ),
    "WEBAUTHN_NAME_INUSE": (
        _("%(name)s is already associated with a credential."),
        "error",
    ),
    "WEBAUTHN_NAME_NOT_FOUND": (
        _("%(name)s not registered with current user."),
        "error",
    ),
    "WEBAUTHN_CREDENTIAL_DELETED": (
        _("Successfully deleted WebAuthn credential with name: %(name)s"),
        "info",
    ),
    "WEBAUTHN_REGISTER_SUCCESSFUL": (
        _("Successfully added WebAuthn credential with name: %(name)s"),
        "info",
    ),
    "WEBAUTHN_CREDENTIAL_ID_INUSE": (
        _("WebAuthn credential id already registered."),
        "error",
    ),
    "WEBAUTHN_UNKNOWN_CREDENTIAL_ID": (
        _("Unregistered WebAuthn credential id."),
        "error",
    ),
    "WEBAUTHN_ORPHAN_CREDENTIAL_ID": (
        _("WebAuthn credential doesn't belong to any user."),
        "error",
    ),
    "WEBAUTHN_NO_VERIFY": (
        _("Could not verify WebAuthn credential: %(cause)s."),
        "error",
    ),
    "WEBAUTHN_CREDENTIAL_WRONG_USAGE": (
        _("Credential not registered for this use (first or secondary)"),
        "error",
    ),
    "WEBAUTHN_MISMATCH_USER_HANDLE": (
        _("Credential user handle didn't match"),
        "error",
    ),
}


def _default_form_instantiator(
    name: str, cls: t.Type[Form], *args: t.Any, **kwargs: t.Dict[str, t.Any]
) -> Form:
    return cls(*args, **kwargs)


@dataclass
class FormInfo:
    """
    Each view form has a name - assigned by Flask-Security.
    As part of every request, the form is instantiated using (usually) request.form or
    request.json.
    The default instantiator simply uses the class constructor - however
    applications can provide their OWN instantiator which can do pretty much anything
    as long as it returns an instantiated form. The 'cls' argument is optional since
    the instantiator COULD be form specific.

    The instantiator callable will always be called from a flask request context
    and receive the following arguments::

        (name, form_cls_name (optional), **kwargs)

    kwargs will always have `formdata` and often will have `meta`. All kwargs
    must be passed to the underlying form constructor.

    See :py:meth:`flask_security.Security.set_form_info`

    .. versionadded:: 5.1.0
    """

    instantiator: t.Callable[..., Form] = _default_form_instantiator
    cls: t.Optional[t.Type[Form]] = None


def _user_loader(user_id):
    """Load based on fs_uniquifier (alternative_id)."""
    user = _security.datastore.find_user(fs_uniquifier=str(user_id))
    if user and user.active:
        set_request_attr("fs_authn_via", "session")
        return user
    return None


def _request_loader(request):
    # Short-circuit if we have already been called and verified.
    # This can happen since Flask-Login will call us (if no session) and our own
    # decorator @auth_token_required can call us.
    # N.B. we don't call current_user here since that in fact might try and LOAD
    # a user - which would call us again.
    if get_request_attr("fs_authn_via") == "token":
        # Flask-Login 0.6.2 and post Flask 2.2
        if hasattr(g, "_login_user"):
            return g._login_user
        else:  # pragma: no cover
            # pre flask_login 0.6.2 and handle that flask 2.3 is deprecating
            # _request_ctx_stack
            try:
                from flask import _request_ctx_stack

                if hasattr(_request_ctx_stack.top, "user"):
                    return _request_ctx_stack.top.user
            except ImportError:
                pass

    header_key = _security.token_authentication_header
    args_key = _security.token_authentication_key
    header_token = request.headers.get(header_key, None)
    token = request.args.get(args_key, header_token)
    if request.is_json:
        data = request.get_json(silent=True) or {}
        if isinstance(data, dict):
            token = data.get(args_key, token)

    try:
        data = _security.remember_token_serializer.loads(
            token, max_age=_security.token_max_age
        )

        # Version 3.x generated tokens that map to data with 3 elements,
        # and fs_uniquifier was on last element.
        # Version 4.0.0 generates tokens that map to data with only 1 element,
        # which maps to fs_uniquifier.
        # Here we compute uniquifier_index so that we can pick up correct index for
        # matching fs_uniquifier in version 4.0.0 even if token was created with
        # version 3.x
        uniquifier_index = 0 if len(data) == 1 else 2

        if hasattr(_security.datastore.user_model, "fs_token_uniquifier"):
            user = _security.datastore.find_user(
                fs_token_uniquifier=data[uniquifier_index]
            )
        else:
            user = _security.datastore.find_user(fs_uniquifier=data[uniquifier_index])
        if not user.active:
            user = None
    except Exception:
        user = None

    if user and user.verify_auth_token(data):
        set_request_attr("fs_authn_via", "token")
        return user

    return _security.login_manager.anonymous_user()


def _identity_loader():
    if not isinstance(current_user._get_current_object(), AnonymousUserMixin):
        identity = Identity(current_user.fs_uniquifier)
        return identity
    return None


def _on_identity_loaded(sender, identity):
    if hasattr(current_user, "fs_uniquifier"):
        identity.provides.add(UserNeed(current_user.fs_uniquifier))

    for role in getattr(current_user, "roles", []):
        identity.provides.add(RoleNeed(role.name))
        for fsperm in role.get_permissions():
            identity.provides.add(FsPermNeed(fsperm))

    identity.user = current_user


def _get_login_manager(app, anonymous_user):
    lm = LoginManager()
    lm.anonymous_user = anonymous_user or AnonymousUser
    lm.localize_callback = localize_callback
    lm.login_view = f'{cv("BLUEPRINT_NAME", app=app)}.login'
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


def _get_pwd_context(app: "flask.Flask") -> CryptContext:
    pw_hash = cv("PASSWORD_HASH", app=app)
    schemes = cv("PASSWORD_SCHEMES", app=app)
    deprecated = cv("DEPRECATED_PASSWORD_SCHEMES", app=app)
    if pw_hash not in schemes:
        allowed = ", ".join(schemes[:-1]) + " and " + schemes[-1]
        raise ValueError(
            f"Invalid password hashing scheme {pw_hash}. Allowed values are {allowed}"
        )
    cc = CryptContext(
        schemes=schemes,
        default=pw_hash,
        deprecated=deprecated,
        **cv("PASSWORD_HASH_PASSLIB_OPTIONS", app=app),
    )
    return cc


def _get_hashing_context(app: "flask.Flask") -> CryptContext:
    schemes = cv("HASHING_SCHEMES", app=app)
    deprecated = cv("DEPRECATED_HASHING_SCHEMES", app=app)
    return CryptContext(schemes=schemes, deprecated=deprecated)


def _get_serializer(app, name):
    secret_key = app.config.get("SECRET_KEY")
    salt = cv(f"{name.upper()}_SALT", app=app)
    return URLSafeTimedSerializer(secret_key=secret_key, salt=salt)


def _context_processor():
    return dict(url_for_security=url_for_security, security=_security)


class RoleMixin:
    """Mixin for `Role` model definitions"""

    if t.TYPE_CHECKING:  # pragma: no cover

        def __init__(self) -> None:
            self.permissions: t.Optional[t.List[str]]

    def __eq__(self, other):
        return self.name == other or self.name == getattr(other, "name", None)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.name)

    def get_permissions(self) -> set:
        """
        Return set of permissions associated with role.

        .. versionadded:: 3.3.0
        """
        if hasattr(self, "permissions") and self.permissions:
            return set(self.permissions)
        return set()


class UserMixin(BaseUserMixin):
    """Mixin for `User` model definitions"""

    def get_id(self) -> str:
        """Returns the user identification attribute. 'Alternative-token' for
        Flask-Login. This is always ``fs_uniquifier``.

        .. versionadded:: 3.4.0
        """
        return str(self.fs_uniquifier)

    @property
    def is_active(self) -> bool:
        """Returns `True` if the user is active."""
        return self.active

    def get_auth_token(self) -> t.Union[str, bytes]:
        """Constructs the user's authentication token.

        :raises ValueError: If ``fs_token_uniquifier`` is part of model but not set.

        Optionally use a separate uniquifier so that changing password doesn't
        invalidate auth tokens.

        This data MUST be securely signed using the ``remember_token_serializer``

        .. versionchanged:: 4.0.0
            If user model has ``fs_token_uniquifier`` - use that (raise ValueError
            if not set). Otherwise fallback to using ``fs_uniquifier``.
        """

        if hasattr(self, "fs_token_uniquifier"):
            if not self.fs_token_uniquifier:
                raise ValueError()
            data = [str(self.fs_token_uniquifier)]
        else:
            data = [str(self.fs_uniquifier)]
        return _security.remember_token_serializer.dumps(data)

    def verify_auth_token(self, data: t.Union[str, bytes]) -> bool:
        """
        Perform additional verification of contents of auth token.
        Prior to this being called the token has been validated (via signing)
        and has not expired.

        :param data: the data as formulated by :meth:`get_auth_token`

        .. versionadded:: 3.3.0

        .. versionchanged:: 4.0.0
            If user model has ``fs_token_uniquifier`` - use that otherwise
            use ``fs_uniquifier``.
        """

        # Version 3.x generated tokens that map to data with 3 elements,
        # and fs_uniquifier was on last element.
        # Version 4.0.0 generates tokens that map to data with only 1 element,
        # which maps to fs_uniquifier.
        # Here we compute uniquifier_index so that we can pick up correct index for
        # matching fs_uniquifier in version 4.0.0 even if token was created with
        # version 3.x
        uniquifier_index = 0 if len(data) == 1 else 2

        if hasattr(self, "fs_token_uniquifier"):
            return data[uniquifier_index] == self.fs_token_uniquifier

        return data[uniquifier_index] == self.fs_uniquifier

    def has_role(self, role: t.Union[str, "Role"]) -> bool:
        """Returns `True` if the user identifies with the specified role.

        :param role: A role name or `Role` instance"""
        if isinstance(role, str):
            return role in (role.name for role in self.roles)
        else:
            return role in self.roles

    def has_permission(self, permission: str) -> bool:
        """
        Returns `True` if user has this permission (via a role it has).

        :param permission: permission string name

        .. versionadded:: 3.3.0

        """
        for role in self.roles:
            if permission in role.get_permissions():
                return True
        return False

    def get_security_payload(self) -> t.Dict[str, t.Any]:
        """Serialize user object as response payload.
        Override this to return any/all of the user object in JSON responses.
        Return a dict.
        """
        return {}

    def get_redirect_qparams(
        self, existing: t.Optional[t.Dict[str, t.Any]] = None
    ) -> t.Dict[str, t.Any]:
        """Return user info that will be added to redirect query params.

        :param existing: A dict that will be updated.
        :return: A dict whose keys will be query params and values will be query values.

        The returned dict will always have an 'identity' key/value.
        If the User Model contains 'email', an 'email' key/value will added.
        All keys provided in 'existing' will also be merged in.

        .. versionadded:: 3.2.0

        .. versionchanged:: 4.0.0
            Add 'identity' using UserMixin.calc_username() - email is optional.
        """
        if not existing:
            existing = {}
        if hasattr(self, "email"):
            existing.update({"email": self.email})
        existing.update({"identity": self.calc_username()})
        return existing

    def verify_and_update_password(self, password: str) -> bool:
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

    def calc_username(self) -> str:
        """Come up with the best 'username' based on how the app
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

    def us_send_security_token(self, method: str, **kwargs: t.Any) -> t.Optional[str]:
        """Generate and send the security code for unified sign in.

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

    def tf_send_security_token(self, method: str, **kwargs: t.Any) -> t.Optional[str]:
        """Generate and send the security code for two-factor.

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


class WebAuthnMixin:
    def get_user_mapping(self) -> t.Dict[str, t.Any]:
        """
        Return the filter needed by find_user() to get the user
        associated with this webauthn credential.
        Note that this probably has to be overridden using mongoengine.

        .. versionadded:: 5.0.0
        """
        return dict(id=self.user_id)  # type: ignore


class AnonymousUser(AnonymousUserMixin):
    """AnonymousUser definition"""

    def __init__(self):
        self.roles = ImmutableList()

    def has_role(self, *args):
        """Returns `False`"""
        return False


class Security:
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
    :param two_factor_select_form: set form for selecting between active 2FA methods
    :param mf_recovery_codes_form: set form for retrieving and setting recovery codes
    :param mf_recovery_form: set form for multi factor recovery
    :param us_signin_form: set form for the unified sign in view
    :param us_setup_form: set form for the unified sign in setup view
    :param us_setup_validate_form: set form for the unified sign in setup validate view
    :param us_verify_form: set form for re-authenticating due to freshness check
    :param wan_register_form: set form for registering a webauthn security key
    :param wan_register_response_form: set form for registering a webauthn security key
    :param wan_signin_form: set form for authenticating with a webauthn security key
    :param wan_signin_response_form: set form for authenticating with a webauthn
    :param wan_delete_form: set form for deleting a webauthn security key
    :param wan_verify_form: set form for using a webauthn key to verify authenticity
    :param anonymous_user: class to use for anonymous user
    :param mail_util_cls: Class to use for sending emails. Defaults to :class:`MailUtil`
    :param password_util_cls: Class to use for password normalization/validation.
     Defaults to :class:`PasswordUtil`
    :param phone_util_cls: Class to use for phone number utilities.
     Defaults to :class:`PhoneUtil`
    :param render_template: function to use to render templates. The default is Flask's
     render_template() function.
    :param totp_cls: Class to use as TOTP factory. Defaults to :class:`Totp`
    :param username_util_cls: Class to use for normalizing and validating usernames.
        Defaults to :class:`UsernameUtil`
    :param webauthn_util_cls: Class to use for customizing WebAuthn registration
        and signin. Defaults to :class:`WebauthnUtil`
    :param mf_recovery_codes_util_cls: Class for generating, checking, encrypting
        and decrypting recovery codes. Defaults to :class:`MfRecoveryCodesUtil`
    :param oauth: An instance of authlib.integrations.flask_client.OAuth

    .. tip::
        Be sure that all your configuration values have been set PRIOR to
        instantiating this class. Some configuration values are set as attributes
        on the instance and therefore won't track any changes.

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

    .. versionadded:: 4.0.0
        ``mail_util_cls`` added to isolate mailing handling.
        ``password_util_cls`` added to encapsulate password validation/normalization.

    .. versionadded:: 4.1.0
        ``username_util_cls`` added to encapsulate username handling.

    .. versionadded:: 5.0.0
        ``wan_register_form``, ``wan_register_response_form``,
         ``webauthn_signin_form``, ``wan_signin_response_form``,
         ``webauthn_delete_form``, ``webauthn_verify_form``, ``tf_select_form``.
    .. versionadded:: 5.0.0
        ``WebauthnUtil`` class.
    .. versionadded:: 5.0.0
        Added support for multi-factor recovery codes ``mf_recovery_codes_form``,
        ``mf_recovery_form``.
    .. versionadded:: 5.1.0
        ``mf_recovery_codes_util_cls``, ``oauth``

    .. deprecated:: 4.0.0
        ``send_mail`` and ``send_mail_task``. Replaced with ``mail_util_cls``.
        ``two_factor_verify_password_form`` removed.
        ``password_validator`` removed in favor of the new ``password_util_cls``.

    .. deprecated:: 5.0.0
        Passing in a LoginManager instance. Removed in 5.1.0
    .. deprecated:: 5.0.0
        json_encoder_cls is no longer honored since Flask 2.2 has deprecated it.
    """

    def __init__(
        self,
        app: t.Optional["flask.Flask"] = None,
        datastore: t.Optional["UserDatastore"] = None,
        register_blueprint: bool = True,
        login_form: t.Type[LoginForm] = LoginForm,
        verify_form: t.Type[VerifyForm] = VerifyForm,
        confirm_register_form: t.Type[ConfirmRegisterForm] = ConfirmRegisterForm,
        register_form: t.Type[RegisterForm] = RegisterForm,
        forgot_password_form: t.Type[ForgotPasswordForm] = ForgotPasswordForm,
        reset_password_form: t.Type[ResetPasswordForm] = ResetPasswordForm,
        change_password_form: t.Type[ChangePasswordForm] = ChangePasswordForm,
        send_confirmation_form: t.Type[SendConfirmationForm] = SendConfirmationForm,
        passwordless_login_form: t.Type[PasswordlessLoginForm] = PasswordlessLoginForm,
        two_factor_verify_code_form: t.Type[
            TwoFactorVerifyCodeForm
        ] = TwoFactorVerifyCodeForm,
        two_factor_setup_form: t.Type[TwoFactorSetupForm] = TwoFactorSetupForm,
        two_factor_rescue_form: t.Type[TwoFactorRescueForm] = TwoFactorRescueForm,
        two_factor_select_form: t.Type[TwoFactorSelectForm] = TwoFactorSelectForm,
        mf_recovery_codes_form: t.Type[MfRecoveryCodesForm] = MfRecoveryCodesForm,
        mf_recovery_form: t.Type[MfRecoveryForm] = MfRecoveryForm,
        us_signin_form: t.Type[UnifiedSigninForm] = UnifiedSigninForm,
        us_setup_form: t.Type[UnifiedSigninSetupForm] = UnifiedSigninSetupForm,
        us_setup_validate_form: t.Type[
            UnifiedSigninSetupValidateForm
        ] = UnifiedSigninSetupValidateForm,
        us_verify_form: t.Type[UnifiedVerifyForm] = UnifiedVerifyForm,
        wan_register_form: t.Type[WebAuthnRegisterForm] = WebAuthnRegisterForm,
        wan_register_response_form: t.Type[
            WebAuthnRegisterResponseForm
        ] = WebAuthnRegisterResponseForm,
        wan_signin_form: t.Type[WebAuthnSigninForm] = WebAuthnSigninForm,
        wan_signin_response_form: t.Type[
            WebAuthnSigninResponseForm
        ] = WebAuthnSigninResponseForm,
        wan_delete_form: t.Type[WebAuthnDeleteForm] = WebAuthnDeleteForm,
        wan_verify_form: t.Type[WebAuthnVerifyForm] = WebAuthnVerifyForm,
        anonymous_user: t.Optional[t.Type["flask_login.AnonymousUserMixin"]] = None,
        mail_util_cls: t.Type["MailUtil"] = MailUtil,
        password_util_cls: t.Type["PasswordUtil"] = PasswordUtil,
        phone_util_cls: t.Type["PhoneUtil"] = PhoneUtil,
        render_template: t.Callable[..., str] = default_render_template,
        totp_cls: t.Type["Totp"] = Totp,
        username_util_cls: t.Type["UsernameUtil"] = UsernameUtil,
        webauthn_util_cls: t.Type["WebauthnUtil"] = WebauthnUtil,
        mf_recovery_codes_util_cls: t.Type["MfRecoveryCodesUtil"] = MfRecoveryCodesUtil,
        oauth: t.Optional["OAuth"] = None,
        **kwargs: t.Any,
    ):
        # to be nice and hopefully avoid backwards compat issues - we still accept
        # kwargs - but we don't do anything with them. If caller sends in some -
        # output a deprecation warning
        if len(kwargs) > 0:
            warnings.warn(
                "kwargs passed to the constructor are now ignored",
                DeprecationWarning,
                stacklevel=4,
            )
        self.app = app
        self._datastore = datastore
        self._register_blueprint = register_blueprint
        self.anonymous_user = anonymous_user
        self.mail_util_cls = mail_util_cls
        self.password_util_cls = password_util_cls
        self.phone_util_cls = phone_util_cls
        self.render_template = render_template
        self.totp_cls = totp_cls
        self.username_util_cls = username_util_cls
        self.webauthn_util_cls = webauthn_util_cls
        self.mf_recovery_codes_util_cls = mf_recovery_codes_util_cls
        self._oauth = oauth

        # Forms - we create a list from constructor.
        # BC - in init_app we will allow override of class.
        self.forms = {
            "login_form": FormInfo(cls=login_form),
            "verify_form": FormInfo(cls=verify_form),
            "confirm_register_form": FormInfo(cls=confirm_register_form),
            "register_form": FormInfo(cls=register_form),
            "forgot_password_form": FormInfo(cls=forgot_password_form),
            "reset_password_form": FormInfo(cls=reset_password_form),
            "change_password_form": FormInfo(cls=change_password_form),
            "send_confirmation_form": FormInfo(cls=send_confirmation_form),
            "passwordless_login_form": FormInfo(cls=passwordless_login_form),
            "two_factor_verify_code_form": FormInfo(cls=two_factor_verify_code_form),
            "two_factor_setup_form": FormInfo(cls=two_factor_setup_form),
            "two_factor_rescue_form": FormInfo(cls=two_factor_rescue_form),
            "two_factor_select_form": FormInfo(cls=two_factor_select_form),
            "mf_recovery_codes_form": FormInfo(cls=mf_recovery_codes_form),
            "mf_recovery_form": FormInfo(cls=mf_recovery_form),
            "us_signin_form": FormInfo(cls=us_signin_form),
            "us_setup_form": FormInfo(cls=us_setup_form),
            "us_setup_validate_form": FormInfo(cls=us_setup_validate_form),
            "us_verify_form": FormInfo(cls=us_verify_form),
            "wan_register_form": FormInfo(cls=wan_register_form),
            "wan_register_response_form": FormInfo(cls=wan_register_response_form),
            "wan_signin_form": FormInfo(cls=wan_signin_form),
            "wan_signin_response_form": FormInfo(cls=wan_signin_response_form),
            "wan_delete_form": FormInfo(cls=wan_delete_form),
            "wan_verify_form": FormInfo(cls=wan_verify_form),
        }

        # Attributes not settable from init.
        self._unauthn_handler: t.Callable[
            [t.List[str], t.Optional[t.Dict[str, str]]], "ResponseValue"
        ] = default_unauthn_handler
        self._reauthn_handler: t.Callable[
            [timedelta, timedelta], "ResponseValue"
        ] = default_reauthn_handler
        self._unauthz_handler: t.Callable[
            [str, t.Optional[t.List[str]]], "ResponseValue"
        ] = default_unauthz_handler
        self._unauthorized_callback: t.Optional[t.Callable[[], "ResponseValue"]] = None
        self._render_json: t.Callable[
            [t.Dict[str, t.Any], int, t.Optional[t.Dict[str, str]], t.Optional["User"]],
            "ResponseValue",
        ] = default_render_json
        self._want_json: t.Callable[["Request"], bool] = default_want_json

        # Type attributes that we don't initialize until init_app time.
        self.remember_token_serializer: URLSafeTimedSerializer
        self.login_serializer: URLSafeTimedSerializer
        self.reset_serializer: URLSafeTimedSerializer
        self.confirm_serializer: URLSafeTimedSerializer
        self.us_setup_serializer: URLSafeTimedSerializer
        self.tf_validity_serializer: URLSafeTimedSerializer
        self.wan_serializer: URLSafeTimedSerializer
        self.principal: Principal
        self.pwd_context: CryptContext
        self.hashing_context: CryptContext
        self._context_processors: t.Dict[
            str, t.List[t.Callable[[], t.Dict[str, t.Any]]]
        ] = {}
        self.i18n_domain: FsDomain
        self.datastore: "UserDatastore"
        self.register_blueprint: bool
        self.two_factor_plugins: TfPlugin
        self.oauthglue: t.Optional[OAuthGlue] = None

        self.login_manager: "flask_login.LoginManager"
        self._mail_util: MailUtil
        self._phone_util: PhoneUtil
        self._password_util: PasswordUtil
        self._redirect_validate_re: re.Pattern
        self._totp_factory: "Totp"
        self._username_util: UsernameUtil
        self._mf_recovery_codes_util: MfRecoveryCodesUtil

        # We add forms, config etc as attributes - which of course mypy knows
        # nothing about. Add necessary attributes here to keep mypy happy
        self.trackable: bool = False
        self.confirmable: bool = False
        self.registerable: bool = False
        self.changeable: bool = False
        self.recoverable: bool = False
        self.two_factor: bool = False
        self.unified_signin: bool = False
        self.passwordless: bool = False
        self.webauthn: bool = False

        # Redirect URLs
        self.login_error_view: str = ""
        self.post_change_view: str = ""
        self.post_login_view: str = ""
        self.post_reset_view: str = ""
        self.reset_view: str = ""
        self.reset_error_view: str = ""
        self.requires_confirmation_error_view: str = ""
        self.two_factor_error_view: str = ""
        self.post_confirm_view: str = ""
        self.confirm_error_view: str = ""

        self.redirect_behavior: t.Optional[str] = None
        self.support_mfa: bool = False

        if app is not None and datastore is not None:
            self.init_app(app, datastore, register_blueprint=register_blueprint)

    def init_app(
        self,
        app: "flask.Flask",
        datastore: t.Optional["UserDatastore"] = None,
        register_blueprint: t.Optional[bool] = None,
        **kwargs: t.Any,
    ) -> None:
        """Initializes the Flask-Security extension for the specified
        application and datastore implementation.

        :param app: The application.
        :param datastore: An instance of a user datastore.
        :param register_blueprint: to register the Security blueprint or not.
        :param kwargs: Can be used to override/initialize any of the constructor
            attributes.

        If you create the Security instance with both an 'app' and 'datastore'
        you shouldn't call this - it will be called as part of the constructor.
        """
        self.app = app

        if datastore:
            self._datastore = datastore
        if not self._datastore:
            raise ValueError("Datastore must be provided")
        self.datastore = self._datastore

        if register_blueprint is not None:
            self._register_blueprint = register_blueprint
        self.register_blueprint = self._register_blueprint

        # default post redirects to APPLICATION_ROOT, which itself defaults to "/"
        app.config.setdefault(
            "SECURITY_POST_LOGIN_VIEW", app.config.get("APPLICATION_ROOT", "/")
        )
        app.config.setdefault(
            "SECURITY_POST_LOGOUT_VIEW", app.config.get("APPLICATION_ROOT", "/")
        )

        for key, value in _default_config.items():
            app.config.setdefault("SECURITY_" + key, value)

        for key, value in _default_messages.items():
            app.config.setdefault("SECURITY_MSG_" + key, value)

        # Override default forms
        # BC - kwarg value here overrides init/constructor time
        # BC - we allow forms to be set from config
        # Can't wait for assignment expressions.
        form_names = [
            "login_form",
            "verify_form",
            "confirm_register_form",
            "register_form",
            "forgot_password_form",
            "reset_password_form",
            "change_password_form",
            "send_confirmation_form",
            "passwordless_login_form",
            "two_factor_verify_code_form",
            "two_factor_setup_form",
            "two_factor_rescue_form",
            "two_factor_select_form",
            "mf_recovery_form",
            "mf_recovery_codes_form",
            "us_signin_form",
            "us_setup_form",
            "us_setup_validate_form",
            "us_verify_form",
            "wan_register_form",
            "wan_register_response_form",
            "wan_signin_form",
            "wan_signin_response_form",
            "wan_delete_form",
            "wan_verify_form",
        ]
        for form_name in form_names:
            form_cls = kwargs.get(
                form_name, app.config.get(f"SECURITY_{form_name.upper()}", None)
            )
            if form_cls:
                self.forms[form_name].cls = form_cls

        # BC - Allow kwargs to overwrite/init other constructor attributes
        attr_names = [
            "anonymous_user",
            "mail_util_cls",
            "password_util_cls",
            "phone_util_cls",
            "render_template",
            "totp_cls",
        ]
        for attr in attr_names:
            if kwargs.get(attr, None):
                setattr(self, attr, kwargs.get(attr))

        # set all (SECURITY) config items as attributes (minus the SECURITY_ prefix)
        for key, value in get_config(app).items():
            # need to start getting rid of this - especially things like *_URL which
            # should never be referenced
            if not key.endswith("_URL"):
                setattr(self, key.lower(), value)

        identity_loaded.connect_via(app)(_on_identity_loaded)

        if hasattr(self.datastore, "user_model") and not hasattr(
            self.datastore.user_model, "fs_uniquifier"
        ):  # pragma: no cover
            raise ValueError("User model must contain fs_uniquifier as of 4.0.0")

        # Check for pre-4.0 SECURITY_USER_IDENTITY_ATTRIBUTES format
        for uia in cv("USER_IDENTITY_ATTRIBUTES", app=app):  # pragma: no cover
            if not isinstance(uia, dict):
                raise ValueError(
                    "SECURITY_USER_IDENTITY_ATTRIBUTES changed semantics"
                    " in 4.0 - please see release notes."
                )
            if len(list(uia.keys())) != 1:
                raise ValueError(
                    "Each element in SECURITY_USER_IDENTITY_ATTRIBUTES"
                    " must have one and only one key."
                )

        self.login_manager = _get_login_manager(app, self.anonymous_user)
        self._phone_util = self.phone_util_cls(app)
        self._mail_util = self.mail_util_cls(app)
        self._password_util = self.password_util_cls(app)
        self._username_util = self.username_util_cls(app)
        self._webauthn_util = self.webauthn_util_cls(app)
        self._mf_recovery_codes_util = self.mf_recovery_codes_util_cls(app)
        rvre = cv("REDIRECT_VALIDATE_RE", app=app)
        if rvre:
            self._redirect_validate_re = re.compile(rvre)

        self.remember_token_serializer = _get_serializer(app, "remember")
        self.login_serializer = _get_serializer(app, "login")
        self.reset_serializer = _get_serializer(app, "reset")
        self.confirm_serializer = _get_serializer(app, "confirm")
        self.us_setup_serializer = _get_serializer(app, "us_setup")
        self.tf_validity_serializer = _get_serializer(app, "two_factor_validity")
        self.wan_serializer = _get_serializer(app, "wan")
        self.principal = _get_principal(app)
        self.pwd_context = _get_pwd_context(app)
        self.hashing_context = _get_hashing_context(app)
        self.i18n_domain = FsDomain(app)

        if cv("WEBAUTHN", app=app) or cv("TWO_FACTOR", app):
            self.support_mfa = True

        if cv("PASSWORDLESS", app=app):
            warnings.warn(
                "The passwordless feature was deprecated in Version 5.0.0"
                " and will be removed in the future. Please use the Unified Signin"
                " feature instead.",
                DeprecationWarning,
                stacklevel=2,
            )
        if cv("USERNAME_ENABLE", app):
            if hasattr(self.datastore, "user_model") and not hasattr(
                self.datastore.user_model, "username"
            ):  # pragma: no cover
                raise ValueError(
                    "User model must contain 'username' if"
                    " SECURITY_USERNAME_ENABLE is True"
                )
            # if not already listed in user identity attributes, add it at the end
            uialist = []
            for uia in cv("USER_IDENTITY_ATTRIBUTES", app=app):
                uialist.append(list(uia.keys())[0])
            if "username" not in uialist:
                uias = cv("USER_IDENTITY_ATTRIBUTES", app=app).copy()
                uias.append(
                    {
                        "username": {
                            "mapper": uia_username_mapper,
                            "case_insensitive": True,
                        }
                    }
                )
                app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"] = uias
                self.user_identity_attributes = uias

            # Add dynamic fields - probably overkill to check if these are our forms.
            fcls = self.forms["register_form"].cls
            if fcls and issubclass(fcls, RegisterFormMixin):
                fcls.username = get_register_username_field(app)
            fcls = self.forms["confirm_register_form"].cls
            if fcls and issubclass(fcls, RegisterFormMixin):
                fcls.username = get_register_username_field(app)
            fcls = self.forms["login_form"].cls
            if fcls and issubclass(fcls, LoginForm):
                fcls.username = login_username_field

        # initialize two-factor plugins. Note that each implementation likely
        # has its own feature flag which will control whether it is active or not.
        self.two_factor_plugins = TfPlugin()
        for name, impl_class in cv("TWO_FACTOR_IMPLEMENTATIONS", app).items():
            module_path, class_name = impl_class.rsplit(".", 1)
            module = importlib.import_module(module_path)
            self.two_factor_plugins.register_tf_impl(
                app, name, getattr(module, class_name)
            )

        if cv("OAUTH_ENABLE", app=app):
            self.oauthglue = OAuthGlue(app, self._oauth)

        # register our blueprint/endpoints
        bp = None
        if self.register_blueprint:
            bp = create_blueprint(app, self, __name__)
            self.two_factor_plugins.create_blueprint(app, bp, self)
            if self.oauthglue:
                self.oauthglue._create_blueprint(app, bp)
            app.register_blueprint(bp)
            app.context_processor(_context_processor)

        if hasattr(app, "cli"):
            from .cli import users, roles

            # Waiting for 3.8 assignment expressions
            un = cv("CLI_USERS_NAME", app, strict=True)
            rn = cv("CLI_ROLES_NAME", app, strict=True)

            if un:
                app.cli.add_command(users, un)
            if rn:
                app.cli.add_command(roles, rn)

        # Migrate from TWO_FACTOR config to generic config.
        for newc, oldc in [
            ("SECURITY_SMS_SERVICE", "SECURITY_TWO_FACTOR_SMS_SERVICE"),
            ("SECURITY_SMS_SERVICE_CONFIG", "SECURITY_TWO_FACTOR_SMS_SERVICE_CONFIG"),
            ("SECURITY_TOTP_SECRETS", "SECURITY_TWO_FACTOR_SECRET"),
            ("SECURITY_TOTP_ISSUER", "SECURITY_TWO_FACTOR_URI_SERVICE_NAME"),
        ]:
            if not app.config.get(newc, None):
                app.config[newc] = app.config.get(oldc, None)

        # Alternate/code authentication configuration checks and setup
        alt_auth = False
        if cv("UNIFIED_SIGNIN", app=app):
            alt_auth = True
            if len(cv("US_ENABLED_METHODS", app=app)) < 1:
                raise ValueError("Must configure some US_ENABLED_METHODS")
            if "sms" in cv(
                "US_ENABLED_METHODS", app=app
            ) and not get_identity_attribute("us_phone_number", app=app):
                warnings.warn(
                    "'sms' was enabled in SECURITY_US_ENABLED_METHODS;"
                    " however 'us_phone_number' not configured in"
                    " SECURITY_USER_IDENTITY_ATTRIBUTES",
                    stacklevel=2,
                )
        if cv("TWO_FACTOR", app=app):
            alt_auth = True
            if len(cv("TWO_FACTOR_ENABLED_METHODS", app=app)) < 1:
                raise ValueError("Must configure some TWO_FACTOR_ENABLED_METHODS")
        if cv("MULTI_FACTOR_RECOVERY_CODES", app=app):
            # These rely on totp to generate
            alt_auth = True

        if alt_auth:
            # cryptography is used to encrypt TOTP secrets
            self._check_modules("cryptography", "TWO_FACTOR or UNIFIED_SIGNIN")

            need_qrcode = (
                cv("UNIFIED_SIGNIN", app=app)
                and "authenticator" in cv("US_ENABLED_METHODS", app=app)
            ) or (
                cv("TWO_FACTOR", app=app)
                and "authenticator" in cv("TWO_FACTOR_ENABLED_METHODS", app=app)
            )
            if need_qrcode:
                self._check_modules("qrcode", "TWO_FACTOR or UNIFIED_SIGNIN")

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
                if self.phone_util_cls == PhoneUtil:
                    self._check_modules("phonenumbers", "SMS")

            secrets = cv("TOTP_SECRETS", app=app)
            issuer = cv("TOTP_ISSUER", app=app)
            if not secrets or not issuer:
                raise ValueError("Both TOTP_SECRETS and TOTP_ISSUER must be set")
            self._totp_factory = self.totp_cls(secrets, issuer)

        if cv("PASSWORD_COMPLEXITY_CHECKER", app=app) == "zxcvbn":
            self._check_modules("zxcvbn", "PASSWORD_COMPLEXITY_CHECKER")

        if cv("WEBAUTHN", app=app):
            self._check_modules("webauthn", "WEBAUTHN")

        if cv("USERNAME_ENABLE", app=app):
            self._check_modules("bleach", "USERNAME_ENABLE")

        # Register so other packages can reference our translations.
        app.jinja_env.globals["_fsdomain"] = self.i18n_domain.gettext

        # Perform CSRF checks. Apps must initialize CSRFProtect PRIOR to
        # initializing us.
        self._csrf_init(app)

        # register our JSON encoder extensions
        setup_json(app, bp)

        app.extensions["security"] = self

    def _check_modules(self, module, config_name):  # pragma: no cover
        from importlib.util import find_spec

        module_exists = find_spec(module)
        if not module_exists:
            raise ValueError(f"{module} is required for {config_name}")

        return module_exists

    @staticmethod
    def _csrf_init(app):
        # various config checks - some of these are opinionated in that there
        # could be a reason for some of these combinations - but in general
        # they cause strange behavior.
        # WTF_CSRF_ENABLED defaults to True if not set in Flask-WTF
        if not app.config.get("WTF_CSRF_ENABLED", True):
            return
        csrf = app.extensions.get("csrf", None)

        # If they don't want ALL mechanisms protected, then they must
        # set WTF_CSRF_CHECK_DEFAULT=False so that our decorators get control.
        if cv("CSRF_PROTECT_MECHANISMS", app=app) != AUTHN_MECHANISMS:
            if not csrf:
                # This isn't good.
                raise ValueError(
                    "CSRF_PROTECT_MECHANISMS defined but"
                    " CsrfProtect not part of application."
                    " Make sure to initialize CSRFProtect prior to"
                    " initializing Flask-Security"
                )
            if app.config.get("WTF_CSRF_CHECK_DEFAULT", True):
                raise ValueError(
                    "WTF_CSRF_CHECK_DEFAULT must be set to False if"
                    " CSRF_PROTECT_MECHANISMS is set"
                )
        # We don't get control unless they turn off WTF_CSRF_CHECK_DEFAULT if
        # they have enabled global CSRFProtect.
        if (
            cv("CSRF_IGNORE_UNAUTH_ENDPOINTS", app=app)
            and csrf
            and app.config.get("WTF_CSRF_CHECK_DEFAULT", False)
        ):
            raise ValueError(
                "To ignore unauth endpoints you must set WTF_CSRF_CHECK_DEFAULT"
                " to False"
            )

        csrf_cookie = cv("CSRF_COOKIE", app=app)
        # We used to have 'key' part of CSRF_COOKIE - and in csrf_cookie_handler
        # we removed that prior to setting the cookie. That was a terrible UI
        # decision since if the user sets the key - they likely will not set
        # all the other important things like samesite, secure etc.
        # Now CSRF_COOKIE_NAME is used for the name - we do the backwards compat
        # magic here
        if csrf_cookie and csrf_cookie.get("key", None):
            app.config["SECURITY_CSRF_COOKIE_NAME"] = csrf_cookie.pop("key")
        if cv("CSRF_COOKIE_NAME", app=app) and not csrf:
            # Common use case is for cookie value to be used as contents for header
            # which is only looked at when CsrfProtect is initialized.
            # Yes, this is opinionated - they can always get CSRF token via:
            # 'get /login'
            raise ValueError(
                "CSRF_COOKIE defined however CsrfProtect not part of application"
            )

        if csrf:
            csrf.exempt("flask_security.views.logout")
        if cv("CSRF_COOKIE_NAME", app=app):
            app.after_request(csrf_cookie_handler)
            # Add configured header to WTF_CSRF_HEADERS
            app.config["WTF_CSRF_HEADERS"].append(cv("CSRF_HEADER", app=app))

    def set_form_info(self, name: str, form_info: FormInfo) -> None:
        """Set form instantiation info.

        :param name: Name of form.
        :param form_info: see :py:class:`FormInfo`

        .. admonition:: Advanced

           Forms (which are all FlaskForms) are instantiated at the start of each
           request. Normally this is done as part of a view by simply calling the
           form class constructor - Flask-WTForms handles filling it in from
           various request attributes.

           The form classes themselves can be extended (e.g. to add or change fields)
           and the derived class can be set at `Security` constructor time,
           `init_app` time, or using this method.

           This default implementation is suitable for most applications.

           Some application might want to control the instantiation of forms, for
           example to be able to inject additional validation services.
           Using this method, a callable `instantiator` can be set that Flask-Security
           will call to return a properly instantiated form.

           .. danger::
            Do not perform any validation as part of instantiation - many views have
            a bunch of logic PRIOR to calling the form validator.

            .. versionadded:: 5.1.0
        """
        if name not in self.forms.keys():
            raise ValueError(f"Unknown form name {name}")
        if form_info.instantiator == _default_form_instantiator and not form_info.cls:
            raise ValueError(
                "If default form instantiator is used, a form class must be provided"
            )
        self.forms[name] = form_info

    def render_json(
        self,
        cb: t.Callable[
            [t.Dict[str, t.Any], int, t.Optional[t.Dict[str, str]], t.Optional["User"]],
            "ResponseValue",
        ],
    ) -> None:
        """Callback to render response payload as JSON.

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
            Note that this has nothing to do with how the response is serialized.
            That is controlled by Flask and starting with Flask 2.2 that is managed
            by sub-classing Flask::JSONProvider. Flask-Security does this to add
            serializing lazy-strings.


        This can be used by applications to unify all their JSON API responses.
        This is called in a request context and should return a Response or something
        Flask can create a Response from.

        .. versionadded:: 3.3.0
        """
        self._render_json = cb

    def want_json(self, fn: t.Callable[["flask.Request"], bool]) -> None:
        """Function that returns True if response should be JSON (based on the request)

        :param fn: Function with the following signature (request)

            :request: Werkzueg/Flask request

        The default implementation returns True if either the Content-Type is
        "application/json" or the best Accept header value is "application/json".

        .. versionadded:: 3.3.0
        """
        self._want_json = fn

    def unauthz_handler(
        self,
        cb: t.Callable[[str, t.Optional[t.List[str]]], "ResponseValue"],
    ) -> None:
        """
        Callback for failed authorization.
        This is called by the :func:`roles_required`, :func:`roles_accepted`,
        :func:`permissions_required`, or :func:`permissions_accepted`
        if a role or permission is missing.

        :param cb: Callback function with signature (func, params)

            :func_name: the decorator function name (e.g. 'roles_required')
            :params: list of what (if any) was passed to the decorator.

        Should return a Response or something Flask can create a Response from.
        Can raise an exception if it is handled as part of
        flask.errorhandler(<exception>)

        With the passed parameters the application could deliver a concise error
        message.

        .. versionadded:: 3.3.0

        .. versionchanged:: 5.1.0
            Pass in the function name, not the function!
        """
        self._unauthz_handler = cb

    def unauthn_handler(
        self,
        cb: t.Callable[[t.List[str], t.Optional[t.Dict[str, str]]], "ResponseValue"],
    ) -> None:
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
        self._unauthn_handler = cb

    def reauthn_handler(
        self, cb: t.Callable[[timedelta, timedelta], "ResponseValue"]
    ) -> None:
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
        self._reauthn_handler = cb

    def unauthorized_handler(self, cb: t.Callable[[], "ResponseValue"]) -> None:
        warnings.warn(
            "'unauthorized_handler' has been replaced with"
            " 'unauthz_handler' and 'unauthn_handler'",
            DeprecationWarning,
            stacklevel=2,
        )
        self._unauthorized_callback = cb

    def _add_ctx_processor(
        self, endpoint: str, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        group = self._context_processors.setdefault(endpoint, [])
        if fn not in group:
            group.append(fn)

    def _run_ctx_processor(self, endpoint: str) -> t.Dict[str, t.Any]:
        rv: t.Dict[str, t.Any] = {}
        for gl in ["global", endpoint]:
            for fn in self._context_processors.setdefault(gl, []):
                rv.update(fn())
        return rv

    def context_processor(self, fn: t.Callable[[], t.Dict[str, t.Any]]) -> None:
        self._add_ctx_processor("global", fn)

    def forgot_password_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("forgot_password", fn)

    def login_context_processor(self, fn: t.Callable[[], t.Dict[str, t.Any]]) -> None:
        self._add_ctx_processor("login", fn)

    def register_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("register", fn)

    def reset_password_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("reset_password", fn)

    def change_password_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("change_password", fn)

    def send_confirmation_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("send_confirmation", fn)

    def send_login_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("send_login", fn)

    def verify_context_processor(self, fn: t.Callable[[], t.Dict[str, t.Any]]) -> None:
        self._add_ctx_processor("verify", fn)

    def mail_context_processor(self, fn: t.Callable[[], t.Dict[str, t.Any]]) -> None:
        self._add_ctx_processor("mail", fn)

    def tf_setup_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("tf_setup", fn)

    def tf_token_validation_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("tf_token_validation", fn)

    def tf_select_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("tf_select", fn)

    def us_signin_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("us_signin", fn)

    def us_setup_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("us_setup", fn)

    def us_verify_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("us_verify", fn)

    def wan_register_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("wan_register", fn)

    def wan_signin_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("wan_signin", fn)

    def wan_verify_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("wan_verify", fn)

    def mf_recovery_codes_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("mf_recovery_codes", fn)

    def mf_recovery_context_processor(
        self, fn: t.Callable[[], t.Dict[str, t.Any]]
    ) -> None:
        self._add_ctx_processor("mf_recovery", fn)
