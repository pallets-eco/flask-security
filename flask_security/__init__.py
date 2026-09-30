"""
flask_security
~~~~~~~~~~~~~~

Flask-Security is a Flask extension that aims to add comprehensive security
to Flask applications.

:copyright: (c) 2012-2019 by Matt Wright.
:copyright: (c) 2019-2026 by J. Christopher Wagner.
:license: MIT, see LICENSE for more details.
"""

from __future__ import annotations

# flake8: noqa: F401
from .changeable import admin_change_password as admin_change_password
from .change_email import ChangeEmailForm as ChangeEmailForm
from .change_username import ChangeUsernameForm as ChangeUsernameForm
from .core import (
    Security as Security,
    RefreshTrackerMixin as RefreshTrackerMixin,
    RoleMixin as RoleMixin,
    UserMixin as UserMixin,
    WebAuthnMixin as WebAuthnMixin,
    FormInfo as FormInfo,
    current_user as current_user,
)
from .datastore import (
    FSQLALiteUserDatastore as FSQLALiteUserDatastore,
    UserDatastore as UserDatastore,
    SQLAlchemyUserDatastore as SQLAlchemyUserDatastore,
    AsaList as AsaList,
    MongoEngineUserDatastore as MongoEngineUserDatastore,
    PeeweeUserDatastore as PeeweeUserDatastore,
    SQLAlchemySessionUserDatastore as SQLAlchemySessionUserDatastore,
)
from .decorators import (
    auth_token_required as auth_token_required,
    anonymous_user_required as anonymous_user_required,
    handle_csrf as handle_csrf,
    http_auth_required as http_auth_required,
    login_required as login_required,
    roles_accepted as roles_accepted,
    roles_required as roles_required,
    auth_required as auth_required,
    permissions_accepted as permissions_accepted,
    permissions_required as permissions_required,
    unauth_csrf as unauth_csrf,
)
from .forms import (
    ChangePasswordForm as ChangePasswordForm,
    ConfirmRegisterForm as ConfirmRegisterForm,
    Form as Form,
    ForgotPasswordForm as ForgotPasswordForm,
    LoginForm as LoginForm,
    LogoutForm as LogoutForm,
    PasswordlessLoginForm as PasswordlessLoginForm,
    RegisterForm as RegisterForm,
    RegisterFormV2 as RegisterFormV2,
    ResetPasswordForm as ResetPasswordForm,
    SendConfirmationForm as SendConfirmationForm,
    TwoFactorRescueForm as TwoFactorRescueForm,
    TwoFactorSetupForm as TwoFactorSetupForm,
    TwoFactorVerifyCodeForm as TwoFactorVerifyCodeForm,
    unique_identity_attribute as unique_identity_attribute,
    UsernameRecoveryForm as UsernameRecoveryForm,
    VerifyForm as VerifyForm,
)
from .mail_util import (
    MailUtil as MailUtil,
    EmailValidateException as EmailValidateException,
)
from .oauth_glue import OAuthGlue as OAuthGlue
from .oauth_provider import FsOAuthProvider as FsOAuthProvider
from .password_util import PasswordUtil as PasswordUtil
from .phone_util import PhoneUtil as PhoneUtil
from .recovery_codes import (
    MfRecoveryCodesUtil as MfRecoveryCodesUtil,
    MfRecoveryForm as MfRecoveryForm,
    MfRecoveryCodesForm as MfRecoveryCodesForm,
)
from .tokens import RefreshTokenForm as RefreshTokenForm
from .signals import (
    change_email_confirmed as change_email_confirmed,
    change_email_instructions_sent as change_email_instructions_sent,
    confirm_instructions_sent as confirm_instructions_sent,
    login_instructions_sent as login_instructions_sent,
    password_changed as password_changed,
    password_reset as password_reset,
    refresh_tracker_created as refresh_tracker_created,
    refresh_tracker_revoked as refresh_tracker_revoked,
    reset_password_instructions_sent as reset_password_instructions_sent,
    tf_code_confirmed as tf_code_confirmed,
    tf_profile_changed as tf_profile_changed,
    tf_security_token_sent as tf_security_token_sent,
    tf_disabled as tf_disabled,
    user_authenticated as user_authenticated,
    user_failed_authn as user_failed_authn,
    user_unauthenticated as user_unauthenticated,
    user_confirmed as user_confirmed,
    user_registered as user_registered,
    user_not_registered as user_not_registered,
    username_recovery_email_sent as username_recovery_email_sent,
    username_changed as username_changed,
    us_security_token_sent as us_security_token_sent,
    us_profile_changed as us_profile_changed,
    wan_deleted as wan_deleted,
    wan_registered as wan_registered,
)
from .totp import Totp as Totp
from .twofactor import tf_send_security_token as tf_send_security_token
from .tf_plugin import TwoFactorSelectForm as TwoFactorSelectForm
from .unified_signin import (
    UnifiedSigninForm as UnifiedSigninForm,
    UnifiedSigninSetupForm as UnifiedSigninSetupForm,
    UnifiedSigninSetupValidateForm as UnifiedSigninSetupValidateForm,
    UnifiedVerifyForm as UnifiedVerifyForm,
    us_send_security_token as us_send_security_token,
)
from .username_util import UsernameUtil as UsernameUtil
from .utils import (
    SmsSenderBaseClass as SmsSenderBaseClass,
    SmsSenderFactory as SmsSenderFactory,
    check_and_get_token_status as check_and_get_token_status,
    check_and_update_authn_fresh as check_and_update_authn_fresh,
    get_hmac as get_hmac,
    get_request_attr as get_request_attr,
    get_url as get_url,
    hash_password as hash_password,
    input_svn as input_svn,
    login_user as login_user,
    logout_user as logout_user,
    lookup_identity as lookup_identity,
    naive_utcnow as naive_utcnow,
    password_breached_validator as password_breached_validator,
    password_complexity_validator as password_complexity_validator,
    password_length_validator as password_length_validator,
    pwned as pwned,
    send_mail as send_mail,
    transform_url as transform_url,
    uia_phone_mapper as uia_phone_mapper,
    uia_email_mapper as uia_email_mapper,
    uia_username_mapper as uia_username_mapper,
    url_for_security as url_for_security,
    verify_password as verify_password,
    verify_and_update_password as verify_and_update_password,
)
from .webauthn import (
    WebAuthnRegisterForm as WebAuthnRegisterForm,
    WebAuthnRegisterResponseForm as WebAuthnRegisterResponseForm,
    WebAuthnSigninForm as WebAuthnSigninForm,
    WebAuthnSigninResponseForm as WebAuthnSigninResponseForm,
    WebAuthnDeleteForm as WebAuthnDeleteForm,
    WebAuthnVerifyForm as WebAuthnVerifyForm,
)
from .webauthn_util import WebauthnUtil as WebauthnUtil

__version__ = "5.9.1"
