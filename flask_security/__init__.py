"""
flask_security
~~~~~~~~~~~~~~

Flask-Security is a Flask extension that aims to add comprehensive security
to Flask applications.

:copyright: (c) 2012-2019 by Matt Wright.
:copyright: (c) 2019-2025 by J. Christopher Wagner.
:license: MIT, see LICENSE for more details.
"""

# flake8: noqa: F401
from .changeable import admin_change_password
from .change_email import ChangeEmailForm
from .change_username import ChangeUsernameForm
from .core import (
    Security,
    RoleMixin,
    UserMixin,
    WebAuthnMixin,
    FormInfo,
    current_user,
)
from .datastore import (
    FSQLALiteUserDatastore,
    UserDatastore,
    SQLAlchemyUserDatastore,
    AsaList,
    MongoEngineUserDatastore,
    PeeweeUserDatastore,
    PonyUserDatastore,
    SQLAlchemySessionUserDatastore,
)
from .decorators import (
    auth_token_required,
    anonymous_user_required,
    handle_csrf,
    http_auth_required,
    login_required,
    roles_accepted,
    roles_required,
    auth_required,
    permissions_accepted,
    permissions_required,
    unauth_csrf,
)
from .forms import (
    ChangePasswordForm,
    ConfirmRegisterForm,
    Form,
    ForgotPasswordForm,
    LoginForm,
    PasswordlessLoginForm,
    RegisterForm,
    RegisterFormV2,
    ResetPasswordForm,
    SendConfirmationForm,
    TwoFactorRescueForm,
    TwoFactorSetupForm,
    TwoFactorVerifyCodeForm,
    unique_identity_attribute,
    UsernameRecoveryForm,
    VerifyForm,
)
from .mail_util import MailUtil, EmailValidateException
from .oauth_glue import OAuthGlue
from .oauth_provider import FsOAuthProvider
from .password_util import PasswordUtil
from .phone_util import PhoneUtil
from .recovery_codes import (
    MfRecoveryCodesUtil,
    MfRecoveryForm,
    MfRecoveryCodesForm,
)
from .signals import (
    change_email_confirmed,
    change_email_instructions_sent,
    confirm_instructions_sent,
    login_instructions_sent,
    password_changed,
    password_reset,
    reset_password_instructions_sent,
    tf_code_confirmed,
    tf_profile_changed,
    tf_security_token_sent,
    tf_disabled,
    user_authenticated,
    user_unauthenticated,
    user_confirmed,
    user_registered,
    user_not_registered,
    username_recovery_email_sent,
    username_changed,
    us_security_token_sent,
    us_profile_changed,
    wan_deleted,
    wan_registered,
)
from .totp import Totp
from .twofactor import tf_send_security_token
from .tf_plugin import TwoFactorSelectForm
from .unified_signin import (
    UnifiedSigninForm,
    UnifiedSigninSetupForm,
    UnifiedSigninSetupValidateForm,
    UnifiedVerifyForm,
    us_send_security_token,
)
from .username_util import UsernameUtil
from .utils import (
    SmsSenderBaseClass,
    SmsSenderFactory,
    check_and_get_token_status,
    get_hmac,
    get_request_attr,
    get_url,
    hash_password,
    check_and_update_authn_fresh,
    login_user,
    logout_user,
    lookup_identity,
    naive_utcnow,
    password_breached_validator,
    password_complexity_validator,
    password_length_validator,
    pwned,
    send_mail,
    transform_url,
    uia_phone_mapper,
    uia_email_mapper,
    uia_username_mapper,
    url_for_security,
    verify_password,
    verify_and_update_password,
)
from .webauthn import (
    WebAuthnRegisterForm,
    WebAuthnRegisterResponseForm,
    WebAuthnSigninForm,
    WebAuthnSigninResponseForm,
    WebAuthnDeleteForm,
    WebAuthnVerifyForm,
)
from .webauthn_util import WebauthnUtil

__version__ = "5.7.0"
