"""
    flask_security.forms
    ~~~~~~~~~~~~~~~~~~~~

    Flask-Security forms module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2017 by CERN.
    :copyright: (c) 2019-2022 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import inspect
import typing as t

from flask import Markup, current_app, request
from flask_login import current_user
from flask_wtf import FlaskForm as BaseForm
from wtforms import (
    BooleanField,
    EmailField,
    Field,
    HiddenField,
    PasswordField,
    RadioField,
    StringField,
    SubmitField,
    TelField,
    ValidationError,
    validators,
)

from wtforms.validators import Optional, StopValidation

from .babel import is_lazy_string, make_lazy_string
from .confirmable import requires_confirmation
from .proxies import _security
from .utils import (
    _,
    _datastore,
    config_value as cv,
    do_flash,
    get_identity_attribute,
    get_message,
    hash_password,
    localize_callback,
    url_for_security,
    validate_redirect_url,
    verify_password,
)

if t.TYPE_CHECKING:  # pragma: no cover
    from .datastore import User

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
    "username": _("Username"),
    "delete": _("Delete"),
    "email_method": _("Set up using email"),
    "authapp_method": _(
        "Set up using an authenticator app (e.g. google, lastpass, authy)"
    ),
    "sms_method": _("Set up using SMS"),
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
            msg = cv("MSG_" + self._original_message, strict=False)
            if msg:
                self.message = make_lazy_string(_local_xlate, msg[0])
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
    """Simple interface to email_validator.
    N.B. Side-effect - if valid email, the field.data is set to the normalized value.
    """

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


def get_form_field_xlate(txt):
    return make_lazy_string(_local_xlate, txt)


def valid_user_email(form, field):
    # Verify email exists in DB - be sure to normalize first.
    # Side-effect - set form.user if field is valid
    uia_email = get_identity_attribute("email")
    form.user = _datastore.find_user(
        case_insensitive=uia_email.get("case_insensitive", False), email=field.data
    )
    if form.user is None:
        raise ValidationError(get_message("USER_DOES_NOT_EXIST")[0])


def unique_user_email(form, field):
    # Verify email not already in DB
    # Assumes field value already normalized - email_validator does this.
    uia_email = get_identity_attribute("email")
    form.existing_email_user = _datastore.find_user(
        case_insensitive=uia_email.get("case_insensitive", False), email=field.data
    )
    if form.existing_email_user is not None:
        msg = get_message("EMAIL_ALREADY_ASSOCIATED", email=field.data)[0]
        raise ValidationError(msg)


def username_validator(form, field):
    # Side-effect - field.data is updated to normalized value.
    msg, field.data = _security._username_util.validate(field.data)
    if msg:
        raise ValidationError(msg)


def unique_username(form, field):
    # Verify username not already in DB
    # Assumes field value already normalized - username_validator does this.
    uia_username = get_identity_attribute("username")
    form.existing_username_user = _datastore.find_user(
        case_insensitive=uia_username.get("case_insensitive", False),
        username=field.data,
    )
    if form.existing_username_user is not None:
        msg = get_message("USERNAME_ALREADY_ASSOCIATED", username=field.data)[0]
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
    for mapping in cv("USER_IDENTITY_ATTRIBUTES"):
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


class Form(BaseForm):
    def __init__(self, *args, **kwargs):
        if current_app.testing:
            self.TIME_LIMIT = None
        super().__init__(*args, **kwargs)


def generic_message(
    detailed_msg: str, generic_msg: str, **kwargs: t.Any
) -> t.Tuple[str, str]:
    if cv("RETURN_GENERIC_RESPONSES"):
        m, c = get_message(generic_msg, **kwargs)
    else:
        m, c = get_message(detailed_msg, **kwargs)
    return m, c


def form_errors_munge(form: Form, fields: t.Dict[str, t.Dict[str, str]]) -> None:
    """
    To support OWASP best practice on unauthenticated endpoints to avoid
    disclosing whether a user exists or not we need to return generic error messages.
    Furthermore, WTForms really likes to place errors on the field itself - which is
    a dead giveaway. We need to move errors from fields to the form.form_errors, and
    replace then with generic msgs.
    """
    if not cv("RETURN_GENERIC_RESPONSES"):  # pragma: no cover
        return

    for fname, rinfo in fields.items():
        field = getattr(form, fname)
        if field.errors:
            field.errors = []
            # If they want to replace that message with a generic message and place
            # it in the generic/form level errors - do that.
            replace_msg = rinfo.get("replace_msg", None)
            if replace_msg:
                form.form_errors.append(get_message(replace_msg)[0])


class UserEmailFormMixin:
    email = EmailField(
        get_form_field_label("email"),
        render_kw={"autocomplete": "email"},
        validators=[email_required, email_validator, valid_user_email],
    )


class UniqueEmailFormMixin:
    email = EmailField(
        get_form_field_label("email"),
        render_kw={"autocomplete": "email"},
        validators=[email_required, email_validator, unique_user_email],
    )


class PasswordFormMixin:
    password = PasswordField(
        get_form_field_label("password"),
        render_kw={"autocomplete": "current-password"},
        validators=[password_required],
    )


class NewPasswordFormMixin:
    password = PasswordField(
        get_form_field_label("password"),
        render_kw={"autocomplete": "new-password"},
        validators=[password_required],
    )


class PasswordConfirmFormMixin:
    password_confirm = PasswordField(
        get_form_field_label("retype_password"),
        render_kw={"autocomplete": "new-password"},
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


class CodeFormMixin:
    code = StringField(
        get_form_field_label("code"),
        render_kw={
            "autocomplete": "one-time-code",
            "inputtype": "numeric",
            "pattern": "[0-9]*",
        },
        validators=[Required()],
    )


register_username_field = StringField(
    get_form_field_label("username"),
    render_kw={"autocomplete": "username"},
    validators=[username_validator, unique_username],
)

login_username_field = StringField(
    get_form_field_label("username"),
    render_kw={"autocomplete": "username"},
    validators=[username_validator],
)


class RegisterFormMixin:
    submit = SubmitField(get_form_field_label("register"))

    # The "username" field is added in init_app if USERNAME_ENABLE is set.
    # This is just a type hint.
    username: t.ClassVar[Field]

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
        self.user: "User" = None  # set by valid_user_email
        if request.method == "GET":
            self.email.data = request.args.get("email", None)

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
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
        self.user: "User" = None  # set by valid_user_email

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
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
        self.user: "User" = None  # set by valid_user_email

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False
        if not self.user.is_active:
            self.email.errors.append(get_message("DISABLED_ACCOUNT")[0])
            return False
        return True


class LoginForm(Form, PasswordFormMixin, NextFormMixin):
    """The default login form"""

    # email field - we don't use valid_user_email since for login
    # with username feature it is potentially optional.
    email = EmailField(
        get_form_field_label("email"),
        render_kw={"autocomplete": "email"},
        validators=[Optional(), email_validator],
    )

    # username is added dynamically based on USERNAME_ENABLED.
    username: t.ClassVar[Field]
    remember = BooleanField(get_form_field_label("remember_me"))
    submit = SubmitField(get_form_field_label("login"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.next.data:
            self.next.data = request.args.get("next", "")
        self.remember.default = cv("DEFAULT_REMEMBER_ME")
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
        self.requires_confirmation: bool = False
        self.user: t.Optional["User"] = None
        # ifield can be set by subclasses to skip identity checks.
        self.ifield: t.Optional[Field] = None
        # If True then user has authenticated so we can show detailed errors
        self.user_authenticated = False

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False

        # Stay clear of accessing 'username' unless we added that field.
        # Lots of applications have added their own.
        # To make subclassing easier - if self.ifield has been set we assume
        # subclass has validated and attempted to look up user. It is also
        # responsible to deal with USER_IDENTITY_ATTRIBUTES if it cares.
        if not self.ifield:
            uia_email = get_identity_attribute("email")
            if uia_email and self.email.data:
                self.ifield = self.email
                self.user = _datastore.find_user(
                    case_insensitive=uia_email.get("case_insensitive", False),
                    email=self.email.data,
                )
            elif cv("USERNAME_ENABLE"):
                uia_username = get_identity_attribute("username")
                if uia_username and self.username.data:
                    self.user = _datastore.find_user(
                        case_insensitive=uia_username.get("case_insensitive", False),
                        username=self.username.data,
                    )
                    self.ifield = self.username
            else:
                # A bit of backwards compat - the old LoginForm just had email and
                # any errors would be set on that field.
                if uia_email:
                    self.ifield = self.email

        if self.user is None:
            msg = get_message("USER_DOES_NOT_EXIST")[0]
            if self.ifield:
                self.ifield.errors.append(msg)
            else:
                self.form_errors.append(msg)
            # Reduce timing variation between existing and non-existing users
            hash_password(self.password.data)
            return False
        if not self.user.password:
            # This is result of PASSWORD_REQUIRED=False and UNIFIED_SIGNIN
            self.password.errors.append(get_message("INVALID_PASSWORD")[0])
            # Reduce timing variation between existing and non-existing users
            hash_password(self.password.data)
            return False
        self.password.data = _security._password_util.normalize(self.password.data)
        if not self.user.verify_and_update_password(self.password.data):
            self.password.errors.append(get_message("INVALID_PASSWORD")[0])
            return False

        # At this point the user has successfully authenticated - so it is fine
        # to return detailed errors.
        self.user_authenticated = True
        self.requires_confirmation = requires_confirmation(self.user)
        if self.requires_confirmation:
            self.ifield.errors.append(get_message("CONFIRMATION_REQUIRED")[0])
            return False
        if not self.user.is_active:
            self.ifield.errors.append(get_message("DISABLED_ACCOUNT")[0])
            return False
        return True


class VerifyForm(Form, PasswordFormMixin):
    """The verify authentication form"""

    submit = SubmitField(get_form_field_label("verify_password"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user: "User" = None  # set by view

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):  # pragma: no cover
            return False

        self.password.data = _security._password_util.normalize(self.password.data)
        if not self.user.verify_and_update_password(self.password.data):
            self.password.errors.append(get_message("INVALID_PASSWORD")[0])
            return False
        return True


class ConfirmRegisterForm(Form, RegisterFormMixin, UniqueEmailFormMixin):
    """This form is used for registering when 'confirmable' is set.
    The only difference between this and the other RegisterForm is that
    this one doesn't require re-typing in the password...

    We want to support OWASP best-practice around mitigating user enumeration.
    To that end we run through the entire validation regardless - this allows us
    to still return important bad-password messages.
    In the case of an existing email or username - we set form.existing_xx so that
    the view can decide how to match responses (e.g. json responses always return 200).
    """

    # Password optional when Unified Signin enabled.
    password = PasswordField(
        get_form_field_label("password"),
        render_kw={"autocomplete": "new-password"},
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.existing_username_user = None
        self.existing_email_user = None

    def validate(self, **kwargs: t.Any) -> bool:
        failed = False
        if not super().validate(**kwargs):
            failed = True

        # whether a password is required is a config variable (PASSWORD_REQUIRED).
        # For unified signin there are many other ways to authenticate
        if cv("PASSWORD_REQUIRED") or not cv("UNIFIED_SIGNIN"):
            if not self.password.data or not self.password.data.strip():
                self.password.errors.append(get_message("PASSWORD_NOT_PROVIDED")[0])
                failed = True

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
                failed = True
        return not failed


class RegisterForm(ConfirmRegisterForm, NextFormMixin):

    # Password optional when Unified Signin enabled.
    password_confirm = PasswordField(
        get_form_field_label("retype_password"),
        validators=[
            EqualTo("password", message="RETYPE_PASSWORD_MISMATCH"),
            validators.Optional(),
        ],
    )

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False
        if not cv("UNIFIED_SIGNIN"):
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

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False

        pbad, self.password.data = _security._password_util.validate(
            self.password.data, False, user=current_user
        )
        if pbad:
            self.password.errors.extend(pbad)
            return False
        return True


class ChangePasswordForm(Form):
    """The default change password form"""

    password = PasswordField(
        get_form_field_label("password"), render_kw={"autocomplete": "current-password"}
    )
    new_password = PasswordField(
        get_form_field_label("new_password"),
        render_kw={"autocomplete": "new-password"},
        validators=[password_required],
    )

    new_password_confirm = PasswordField(
        get_form_field_label("retype_password"),
        render_kw={"autocomplete": "new-password"},
        validators=[
            EqualTo("new_password", message="RETYPE_PASSWORD_MISMATCH"),
            password_required,
        ],
    )

    submit = SubmitField(get_form_field_label("change_password"))

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False

        # If user doesn't have a password then the caller (view) has already
        # verified a current fresh session.
        if current_user.password:
            if not self.password.data or not self.password.data.strip():
                self.password.errors.append(get_message("PASSWORD_NOT_PROVIDED")[0])
                return False

            self.password.data = _security._password_util.normalize(self.password.data)
            if not verify_password(current_user.password, self.password.data):
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


class TwoFactorSetupForm(Form):
    """The Two-factor token validation form"""

    setup = RadioField(
        "Available Methods",
        choices=[
            ("email", get_form_field_label("email_method")),
            (
                "authenticator",
                get_form_field_label("authapp_method"),
            ),
            ("sms", get_form_field_label("sms_method")),
            ("disable", get_form_field_xlate(_("Disable two factor authentication"))),
        ],
        validate_choice=False,
    )
    phone = TelField(get_form_field_label("phone"))
    submit = SubmitField(get_form_field_label("submit"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):  # pragma: no cover
            return False
        choices = list(cv("TWO_FACTOR_ENABLED_METHODS"))
        if "email" in choices:
            # backwards compat
            choices.append("mail")
        if not cv("TWO_FACTOR_REQUIRED"):
            choices.append("disable")
        if "setup" not in self.data or self.data["setup"] not in choices:
            self.setup.errors.append(get_message("TWO_FACTOR_METHOD_NOT_AVAILABLE")[0])
            return False
        if self.setup.data == "sms" and self.phone.data and len(self.phone.data) > 0:
            # Somewhat bizarre - but this isn't required the first time around
            # when they select "sms". Then they get a field to fill out with
            # phone number, then Submit again.
            msg = _security._phone_util.validate_phone_number(self.phone.data)
            if msg:
                self.phone.errors = list()
                self.phone.errors.append(msg)
                return False

        return True


class TwoFactorVerifyCodeForm(Form, CodeFormMixin):
    """The Two-factor token validation form"""

    submit = SubmitField(get_form_field_label("submitcode"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # These are set by view.
        self.window: int = 0
        self.primary_method: str = ""
        self.tf_totp_secret: str = ""
        self.user: "User" = None

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):  # pragma: no cover
            return False
        if (
            self.primary_method == "google_authenticator"
            or self.primary_method == "authenticator"
        ):
            self.window = cv("TWO_FACTOR_AUTHENTICATOR_VALIDITY")
        elif self.primary_method == "email" or self.primary_method == "mail":
            self.window = cv("TWO_FACTOR_MAIL_VALIDITY")
        elif self.primary_method == "sms":
            self.window = cv("TWO_FACTOR_SMS_VALIDITY")
        else:
            return False

        # verify entered code with user's totp secret
        if not _security._totp_factory.verify_totp(
            token=self.code.data,
            totp_secret=self.tf_totp_secret,
            user=self.user,
            window=self.window,
        ):
            self.code.errors.append(get_message("TWO_FACTOR_INVALID_TOKEN")[0])
            return False

        return True


class TwoFactorRescueForm(Form):
    """The Two-factor Rescue validation form"""

    # rescue options - additional options are generated in set_rescue_options()
    help_setup = RadioField(
        "Trouble Accessing Your Account?/Lost Mobile Device?",
        choices=[
            ("help", "Contact Administrator"),
        ],
    )
    submit = SubmitField(get_form_field_label("submit"))


class MfRecoveryCodesForm(Form):
    """Generate and fetch recovery codes"""

    show_codes = SubmitField(get_form_field_xlate(_("Show Recovery Codes")))
    generate_new_codes = SubmitField(
        get_form_field_xlate(_("Generate New Recovery Codes"))
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):  # pragma: no cover
            return False
        return True


class MfRecoveryForm(Form):
    code = StringField(
        get_form_field_xlate(_("Recovery Code")),
        validators=[Required()],
    )
    submit = SubmitField(get_form_field_label("submitcode"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # filled by view
        self.user: "User" = None

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):  # pragma: no cover
            return False
        codes = _datastore.mf_get_recovery_codes(self.user)
        if self.code.data not in codes:
            self.code.errors.append(get_message("INVALID_RECOVERY_CODE")[0])
            return False
        return True
