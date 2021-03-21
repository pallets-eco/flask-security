"""
    flask_security.forms
    ~~~~~~~~~~~~~~~~~~~~

    Flask-Security forms module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2017 by CERN.
    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import inspect

from flask import Markup, current_app, request
from flask_login import current_user
from flask_wtf import FlaskForm as BaseForm
from werkzeug.local import LocalProxy
from wtforms import (
    BooleanField,
    Field,
    HiddenField,
    PasswordField,
    RadioField,
    StringField,
    SubmitField,
    ValidationError,
    validators,
)
from wtforms.fields.html5 import EmailField
from wtforms.validators import StopValidation

from .babel import is_lazy_string, make_lazy_string
from .confirmable import requires_confirmation
from .utils import (
    _,
    _datastore,
    config_value,
    do_flash,
    find_user,
    get_identity_attribute,
    get_message,
    hash_password,
    localize_callback,
    url_for_security,
    validate_redirect_url,
)

# Convenient references
_security = LocalProxy(lambda: current_app.extensions["security"])

_default_field_labels = {
    "email": _("Email Address"),
    "password": _("Password"),
    "remember_me": _("Remember Me"),
    "login": _("Login"),
    "signin": _("Sign In"),
    "register": _("Register"),
    "send_confirmation": _("Resend Confirmation Instructions"),
    "recover_password": _("Recover Password"),
    "reset_password": _("Reset Password"),
    "retype_password": _("Retype Password"),
    "new_password": _("New Password"),
    "change_password": _("Change Password"),
    "send_login_link": _("Send Login Link"),
    "verify_password": _("Verify Password"),
    "change_method": _("Change Method"),
    "phone": _("Phone Number"),
    "code": _("Authentication Code"),
    "submit": _("Submit"),
    "submitcode": _("Submit Code"),
    "error": _("Error(s)"),
    "identity": _("Identity"),
    "sendcode": _("Send Code"),
    "passcode": _("Passcode"),
}


class ValidatorMixin:
    """
    This is called at import time - so there is no app context.
    Validators have state - namely self.message - but we need that
    xlated on a per-request basis. So we want a lazy_string - but we can't create
    that until we are in an app context.
    """

    def __init__(self, *args, **kwargs):
        # If the message is available from config[MSG_xx] then it can be xlated.
        # Otherwise it will be used as is.
        if "message" in kwargs:
            self._original_message = kwargs["message"]
            del kwargs["message"]
        else:
            self._original_message = None
        super().__init__(*args, **kwargs)

    def __call__(self, form, field):
        if self._original_message and (
            not is_lazy_string(self.message) and not self.message
        ):
            # Creat on first usage within app context.
            cv = config_value("MSG_" + self._original_message)
            if cv:
                self.message = make_lazy_string(_local_xlate, cv[0])
            else:
                self.message = self._original_message
        return super().__call__(form, field)


class EqualTo(ValidatorMixin, validators.EqualTo):
    pass


class Required(ValidatorMixin, validators.DataRequired):
    pass


class Length(ValidatorMixin, validators.Length):
    pass


class EmailValidation:
    """Simple interface to email_validator."""

    def __call__(self, form, field):
        if field.data is None:  # pragma: no cover
            raise ValidationError(get_message("EMAIL_NOT_PROVIDED")[0])

        try:
            field.data = _security._mail_util.validate(field.data)
        except ValueError:
            msg = get_message("INVALID_EMAIL_ADDRESS")[0]
            # we stop further validators if email isn't valid.
            # TODO: email_validator provides some really nice error messages - however
            # they aren't localized. And there isn't an easy way to add multiple
            # errors at once.
            raise StopValidation(msg)


email_required = Required(message="EMAIL_NOT_PROVIDED")
email_validator = EmailValidation()
password_required = Required(message="PASSWORD_NOT_PROVIDED")


def _local_xlate(text):
    """LazyStrings need to be evaluated in the context of a request
    where _security.i18_domain is available.
    """
    return localize_callback(text)


def get_form_field_label(key):
    """This is called during import since form fields are declared as part of
    class. Thus can't call 'localize_callback' until we need to actually
    translate/render form.
    """
    return make_lazy_string(_local_xlate, _default_field_labels.get(key, ""))


def unique_user_email(form, field):
    uia_email = get_identity_attribute("email")
    norm_email = _security._mail_util.normalize(field.data)
    if (
        _datastore.find_user(
            case_insensitive=uia_email.get("case_insensitive", False), email=norm_email
        )
        is not None
    ):
        msg = get_message("EMAIL_ALREADY_ASSOCIATED", email=norm_email)[0]
        raise ValidationError(msg)


def unique_identity_attribute(form, field):
    """A validator that checks the field data against all configured
    SECURITY_USER_IDENTITY_ATTRIBUTES.
    This can be used as part of registration.

    Be aware that the "mapper" function likely also normalizes the input in addition
    to validating it.

    :param form:
    :param field:
    :return: Nothing; if field data corresponds to an existing User, ValidationError
        is raised.
    """
    for mapping in config_value("USER_IDENTITY_ATTRIBUTES"):
        attr = list(mapping.keys())[0]
        details = mapping[attr]
        idata = details["mapper"](field.data)
        if idata:
            if _datastore.find_user(
                case_insensitive=details.get("case_insensitive", False), **{attr: idata}
            ):
                msg = get_message(
                    "IDENTITY_ALREADY_ASSOCIATED", attr=attr, value=idata
                )[0]
                raise ValidationError(msg)


def valid_user_email(form, field):
    # Verify email exists in DB - be sure to normalize first.
    uia_email = get_identity_attribute("email")
    norm_email = _security._mail_util.normalize(field.data)
    form.user = _datastore.find_user(
        case_insensitive=uia_email.get("case_insensitive", False), email=norm_email
    )
    if form.user is None:
        raise ValidationError(get_message("USER_DOES_NOT_EXIST")[0])


class Form(BaseForm):
    def __init__(self, *args, **kwargs):
        if current_app.testing:
            self.TIME_LIMIT = None
        super().__init__(*args, **kwargs)


class EmailFormMixin:
    email = EmailField(
        get_form_field_label("email"), validators=[email_required, email_validator]
    )


class UserEmailFormMixin:
    user = None
    email = EmailField(
        get_form_field_label("email"),
        validators=[email_required, email_validator, valid_user_email],
    )


class UniqueEmailFormMixin:
    email = EmailField(
        get_form_field_label("email"),
        validators=[email_required, email_validator, unique_user_email],
    )


class PasswordFormMixin:
    password = PasswordField(
        get_form_field_label("password"), validators=[password_required]
    )


class NewPasswordFormMixin:
    password = PasswordField(
        get_form_field_label("password"), validators=[password_required]
    )


class PasswordConfirmFormMixin:
    password_confirm = PasswordField(
        get_form_field_label("retype_password"),
        validators=[
            EqualTo("password", message="RETYPE_PASSWORD_MISMATCH"),
            password_required,
        ],
    )


class NextFormMixin:
    next = HiddenField()

    def validate_next(self, field):
        if field.data and not validate_redirect_url(field.data):
            field.data = ""
            do_flash(*get_message("INVALID_REDIRECT"))
            raise ValidationError(get_message("INVALID_REDIRECT")[0])


class RegisterFormMixin:
    submit = SubmitField(get_form_field_label("register"))

    def to_dict(self, only_user):
        """
        Return form data as dictionary
        :param only_user: bool, if True then only fields that have
        corresponding members in UserModel are returned
        :return: dict
        """

        def is_field_and_user_attr(member):
            if not isinstance(member, Field):
                return False

            # If only fields recorded on UserModel should be returned,
            # perform check on user model, else return True
            if only_user is True:
                return hasattr(_datastore.user_model, member.name)
            else:
                return True

        fields = inspect.getmembers(self, is_field_and_user_attr)
        return {key: value.data for key, value in fields}


class SendConfirmationForm(Form, UserEmailFormMixin):
    """The default send confirmation form"""

    submit = SubmitField(get_form_field_label("send_confirmation"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if request.method == "GET":
            self.email.data = request.args.get("email", None)

    def validate(self):
        if not super().validate():
            return False
        if self.user.confirmed_at is not None:
            self.email.errors.append(get_message("ALREADY_CONFIRMED")[0])
            return False
        return True


class ForgotPasswordForm(Form, UserEmailFormMixin):
    """The default forgot password form"""

    submit = SubmitField(get_form_field_label("recover_password"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.requires_confirmation = False

    def validate(self):
        if not super().validate():
            return False
        if not self.user.is_active:
            self.email.errors.append(get_message("DISABLED_ACCOUNT")[0])
            return False
        self.requires_confirmation = requires_confirmation(self.user)
        if self.requires_confirmation:
            self.email.errors.append(get_message("CONFIRMATION_REQUIRED")[0])
            return False
        return True


class PasswordlessLoginForm(Form, UserEmailFormMixin):
    """The passwordless login form"""

    submit = SubmitField(get_form_field_label("send_login_link"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self):
        if not super().validate():
            return False
        if not self.user.is_active:
            self.email.errors.append(get_message("DISABLED_ACCOUNT")[0])
            return False
        return True


class LoginForm(Form, NextFormMixin):
    """The default login form"""

    email = EmailField(get_form_field_label("email"), validators=[email_required])
    password = PasswordField(
        get_form_field_label("password"), validators=[password_required]
    )
    remember = BooleanField(get_form_field_label("remember_me"))
    submit = SubmitField(get_form_field_label("login"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.next.data:
            self.next.data = request.args.get("next", "")
        self.remember.default = config_value("DEFAULT_REMEMBER_ME")
        if (
            current_app.extensions["security"].recoverable
            and not self.password.description
        ):
            html = Markup(
                '<a href="{url}">{message}</a>'.format(
                    url=url_for_security("forgot_password"),
                    message=get_message("FORGOT_PASSWORD")[0],
                )
            )
            self.password.description = html
        self.requires_confirmation = False

    def validate(self):
        if not super().validate():
            return False

        # Historically, this used get_user() which would look at all
        # USER_IDENTITY_ATTRIBUTES - even though the field name is 'email'
        # We keep that behavior (for now) as we transition to find_user.
        self.user = find_user(self.email.data)

        if self.user is None:
            self.email.errors.append(get_message("USER_DOES_NOT_EXIST")[0])
            # Reduce timing variation between existing and non-existing users
            hash_password(self.password.data)
            return False
        if not self.user.password:
            self.password.errors.append(get_message("PASSWORD_NOT_SET")[0])
            # Reduce timing variation between existing and non-existing users
            hash_password(self.password.data)
            return False
        self.password.data = _security._password_util.normalize(self.password.data)
        if not self.user.verify_and_update_password(self.password.data):
            self.password.errors.append(get_message("INVALID_PASSWORD")[0])
            return False
        self.requires_confirmation = requires_confirmation(self.user)
        if self.requires_confirmation:
            self.email.errors.append(get_message("CONFIRMATION_REQUIRED")[0])
            return False
        if not self.user.is_active:
            self.email.errors.append(get_message("DISABLED_ACCOUNT")[0])
            return False
        return True


class VerifyForm(Form, PasswordFormMixin):
    """The verify authentication form"""

    user = None
    submit = SubmitField(get_form_field_label("verify_password"))

    def validate(self):
        if not super().validate():
            return False

        self.user = current_user
        self.password.data = _security._password_util.normalize(self.password.data)
        if not self.user.verify_and_update_password(self.password.data):
            self.password.errors.append(get_message("INVALID_PASSWORD")[0])
            return False
        return True


class ConfirmRegisterForm(Form, RegisterFormMixin, UniqueEmailFormMixin):
    """This form is used for registering when 'confirmable' is set.
    The only difference between this and the other RegisterForm is that
    this one doesn't require re-typing in the password...
    """

    # Password optional when Unified Signin enabled.
    password = PasswordField(
        get_form_field_label("password"), validators=[validators.Optional()]
    )

    def validate(self):
        if not super().validate():
            return False

        # To support unified sign in - we permit registering with no password.
        if not config_value("UNIFIED_SIGNIN"):
            # password required
            if not self.password.data or not self.password.data.strip():
                self.password.errors.append(get_message("PASSWORD_NOT_PROVIDED")[0])
                return False

        if self.password.data:
            # We do explicit validation here for passwords
            # (rather than write a validator class) for 2 reasons:
            # 1) We want to control which fields are passed -
            #    sometimes that's current_user
            #    other times it's the registration fields.
            # 2) We want to be able to return multiple error messages.
            rfields = {}
            for k, v in self.data.items():
                if hasattr(_datastore.user_model, k):
                    rfields[k] = v
            del rfields["password"]
            pbad, self.password.data = _security._password_util.validate(
                self.password.data, True, **rfields
            )
            if pbad:
                self.password.errors.extend(pbad)
                return False
        return True


class RegisterForm(ConfirmRegisterForm, NextFormMixin):

    # Password optional when Unified Signin enabled.
    password_confirm = PasswordField(
        get_form_field_label("retype_password"),
        validators=[
            EqualTo("password", message="RETYPE_PASSWORD_MISMATCH"),
            validators.Optional(),
        ],
    )

    def validate(self):
        if not super().validate():
            return False
        if not config_value("UNIFIED_SIGNIN"):
            # password_confirm required
            if not self.password_confirm.data or not self.password_confirm.data.strip():
                self.password_confirm.errors.append(
                    get_message("PASSWORD_NOT_PROVIDED")[0]
                )
                return False
        return True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.next.data:
            self.next.data = request.args.get("next", "")


class ResetPasswordForm(Form, NewPasswordFormMixin, PasswordConfirmFormMixin):
    """The default reset password form"""

    submit = SubmitField(get_form_field_label("reset_password"))

    def validate(self):
        if not super().validate():
            return False

        pbad, self.password.data = _security._password_util.validate(
            self.password.data, False, user=current_user
        )
        if pbad:
            self.password.errors.extend(pbad)
            return False
        return True


class ChangePasswordForm(Form, PasswordFormMixin):
    """The default change password form"""

    new_password = PasswordField(
        get_form_field_label("new_password"), validators=[password_required]
    )

    new_password_confirm = PasswordField(
        get_form_field_label("retype_password"),
        validators=[
            EqualTo("new_password", message="RETYPE_PASSWORD_MISMATCH"),
            password_required,
        ],
    )

    submit = SubmitField(get_form_field_label("change_password"))

    def validate(self):
        if not super().validate():
            return False

        self.password.data = _security._password_util.normalize(self.password.data)
        if not current_user.verify_and_update_password(self.password.data):
            self.password.errors.append(get_message("INVALID_PASSWORD")[0])
            return False
        if self.password.data == self.new_password.data:
            self.password.errors.append(get_message("PASSWORD_IS_THE_SAME")[0])
            return False
        pbad, self.new_password.data = _security._password_util.validate(
            self.new_password.data, False, user=current_user
        )
        if pbad:
            self.new_password.errors.extend(pbad)
            return False
        return True


class TwoFactorSetupForm(Form, UserEmailFormMixin):
    """The Two-factor token validation form"""

    setup = RadioField(
        "Available Methods",
        choices=[
            ("email", "Set up using email"),
            (
                "authenticator",
                "Set up using an authenticator app (e.g. google, lastpass, authy)",
            ),
            ("sms", "Set up using SMS"),
            ("disable", "Disable two factor authentication"),
        ],
    )
    phone = StringField(get_form_field_label("phone"))
    submit = SubmitField(get_form_field_label("submit"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self):
        # TODO: the super class validate is never called - thus we have to
        # initialize errors to lists below. It also means that 'email' is never
        # validated - though it isn't required so the mixin might not be correct.
        choices = config_value("TWO_FACTOR_ENABLED_METHODS")
        if "email" in choices:
            # backwards compat
            choices.append("mail")
        if not config_value("TWO_FACTOR_REQUIRED"):
            choices.append("disable")
        if "setup" not in self.data or self.data["setup"] not in choices:
            self.setup.errors = list()
            self.setup.errors.append(get_message("TWO_FACTOR_METHOD_NOT_AVAILABLE")[0])
            return False
        if self.setup.data == "sms" and len(self.phone.data) > 0:
            # Somewhat bizarre - but this isn't required the first time around
            # when they select "sms". Then they get a field to fill out with
            # phone number, then Submit again.
            msg = _security._phone_util.validate_phone_number(self.phone.data)
            if msg:
                self.phone.errors = list()
                self.phone.errors.append(msg)
                return False

        return True


class TwoFactorVerifyCodeForm(Form, UserEmailFormMixin):
    """The Two-factor token validation form"""

    code = StringField(get_form_field_label("code"))
    submit = SubmitField(get_form_field_label("submitcode"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self):
        # codes sent by sms or mail will be valid for another window cycle
        if (
            self.primary_method == "google_authenticator"
            or self.primary_method == "authenticator"
        ):
            self.window = config_value("TWO_FACTOR_AUTHENTICATOR_VALIDITY")
        elif self.primary_method == "email" or self.primary_method == "mail":
            self.window = config_value("TWO_FACTOR_MAIL_VALIDITY")
        elif self.primary_method == "sms":
            self.window = config_value("TWO_FACTOR_SMS_VALIDITY")
        else:
            return False

        # verify entered token with user's totp secret
        if not _security._totp_factory.verify_totp(
            token=self.code.data,
            totp_secret=self.tf_totp_secret,
            user=self.user,
            window=self.window,
        ):
            self.code.errors = list()
            self.code.errors.append(get_message("TWO_FACTOR_INVALID_TOKEN")[0])

            return False

        return True


class TwoFactorRescueForm(Form):
    """The Two-factor Rescue validation form """

    help_setup = RadioField(
        "Trouble Accessing Your Account?",
        choices=[
            ("lost_device", "Can not access mobile device?"),
            ("no_mail_access", "Can not access mail account?"),
        ],
    )
    submit = SubmitField(get_form_field_label("submit"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self):
        if not super().validate():
            return False
        return True
