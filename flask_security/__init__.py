"""
    flask_security
    ~~~~~~~~~~~~~~

    Flask-Security is a Flask extension that aims to add quick and simple
    security via Flask-Login, Flask-Principal, Flask-WTF, and passlib.

    :copyright: (c) 2012-2019 by Matt Wright.
    :copyright: (c) 2019-2023 by J. Christopher Wagner.
    :license: MIT, see LICENSE for more details.
"""

# flake8: noqa: F401
from .changeable import admin_change_password
from .core import (
    Security,
    RoleMixin,
    UserMixin,
    WebAuthnMixin,
    AnonymousUser,
    FormInfo,
    current_user,
)
from .datastore import (
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
    Form,
    ChangePasswordForm,
    ForgotPasswordForm,
    LoginForm,
    RegisterForm,
    ResetPasswordForm,
    PasswordlessLoginForm,
    ConfirmRegisterForm,
    SendConfirmationForm,
    TwoFactorRescueForm,
    TwoFactorSetupForm,
    TwoFactorVerifyCodeForm,
    VerifyForm,
    unique_identity_attribute,
)
from .mail_util import MailUtil
from .oauth_glue import OAuthGlue
from .password_util import PasswordUtil
from .phone_util import PhoneUtil
from .recovery_codes import (
    MfRecoveryCodesUtil,
    MfRecoveryForm,
    MfRecoveryCodesForm,
)
from .signals import (
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
    user_confirmed,
    user_registered,
    user_not_registered,
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
    get_token_status,
    get_url,
    hash_password,
    check_and_update_authn_fresh,
    login_user,
    logout_user,
    lookup_identity,
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

__version__ = "5.1.2"
