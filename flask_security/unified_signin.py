"""
    flask_security.unified_signin
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security Unified Signin module

    :copyright: (c) 2019-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    This implements a unified sign in endpoint - allowing
    authentication via identity and passcode - where identity is configured
    via SECURITY_USER_IDENTITY_ATTRIBUTES, and allowable passcodes are
    one of US_ENABLED_METHODS.

    Finish up:
    - we should be able to add a phone number as part of setup even w/o any METHODS -
      i.e. to allow login with any identity (phone) and a password.

    Consider/Questions:
    - Allow registering/confirming with just a phone number - this likely would require
      a new register/confirm endpoint in order to implement verification.
    - Right now ChangePassword won't work - it requires an existing password - so
      if the user doesn't have one - can't change it. However ForgotPassword will in
      fact allow the user to add a password. Is that sufficient?
    - This also means that there is no way to REMOVE your password once it is setup,
      although user can register without one.
    - separate code validation times for SMS, email, authenticator?
    - token versus code versus passcode? Confusing terminology.

"""

from __future__ import annotations

import time
import typing as t

from flask import current_app
from flask import after_this_request, request, session
from flask_login import current_user
from wtforms import (
    BooleanField,
    PasswordField,
    RadioField,
    SelectMultipleField,
    StringField,
    SubmitField,
    TelField,
    validators,
)
from wtforms.widgets import CheckboxInput

from .confirmable import requires_confirmation
from .decorators import anonymous_user_required, auth_required, unauth_csrf
from .forms import (
    _setup_methods_xlate,
    Form,
    NextFormMixin,
    Required,
    build_form_from_request,
    build_form,
    form_errors_munge,
    generic_message,
    get_form_field_label,
    get_form_field_xlate,
)
from .proxies import _security, _datastore
from .quart_compat import get_quart_status
from .signals import us_profile_changed, us_security_token_sent
from .utils import (
    _,
    SmsSenderFactory,
    base_render_json,
    check_and_get_token_status,
    config_value as cv,
    do_flash,
    get_identity_attributes,
    get_post_login_redirect,
    get_post_verify_redirect,
    get_message,
    get_url,
    get_within_delta,
    is_user_authenticated,
    localize_callback,
    json_error_response,
    login_user,
    lookup_identity,
    propagate_next,
    send_mail,
    url_for_security,
    view_commit,
)
from .twofactor import tf_clean_session
from .webauthn import has_webauthn

if t.TYPE_CHECKING:  # pragma: no cover
    from flask.typing import ResponseValue
    from .datastore import User

if get_quart_status():  # pragma: no cover
    from quart import redirect
else:
    from flask import redirect


def _compute_code_methods():
    # Return list of methods that actually send codes
    return list(set(cv("US_ENABLED_METHODS")) - {"password", "authenticator"})


def _compute_setup_methods():
    # Return list of methods that require setup
    return list(set(cv("US_ENABLED_METHODS")) - {"password"})


def _compute_active_methods(user):
    # Compute methods already setup.
    active_methods = set(cv("US_ENABLED_METHODS")) & set(
        _datastore.us_get_totp_secrets(user).keys()
    )
    if user.password:
        active_methods = active_methods.union({"password"})
    return list(active_methods)


def _compute_active_code_methods(user):
    return list(set(_compute_active_methods(user)) & set(_compute_code_methods()))


def _us_common_validate(form):
    # Be aware - this has side effect on the form - it will fill in
    # the form.user

    # Validate identity - we go in order to figure out which user attribute the
    # request gave us. Note that we give up on the first 'match' even if that
    # doesn't yield a user. Why?
    form.user = lookup_identity(form.identity.data)
    if not form.user:
        form.identity.errors.append(get_message("US_SPECIFY_IDENTITY")[0])
        return False
    if not form.user.is_active:
        form.identity.errors.append(get_message("DISABLED_ACCOUNT")[0])
        return False
    return True


class _UnifiedPassCodeForm(Form):
    """Common form for signin and verify/reauthenticate."""

    # filled in by caller
    user: User

    # Filled in here
    authn_via: str

    # PasswordField so it doesn't show, no autocomplete since it might be a password
    # but it might be a passcode.
    passcode = PasswordField(
        get_form_field_label("passcode"),
        render_kw={
            "placeholder": get_form_field_xlate(_("Code or Password")),
            "autocomplete": "off",
        },
    )
    submit = SubmitField(get_form_field_label("submit"))

    chosen_method = RadioField(
        _("Available Methods"),
        choices=[
            ("email", get_form_field_xlate(_("Via email"))),
            ("sms", get_form_field_xlate(_("Via SMS"))),
        ],
        validators=[validators.Optional()],
    )
    submit_send_code = SubmitField(get_form_field_label("sendcode"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False
        return True

    def validate2(self) -> bool:
        totp_secrets = _datastore.us_get_totp_secrets(self.user)
        if self.submit.data:
            # This is authn - verify passcode/password
            # Since we have a unique totp_secret for each method - we
            # can figure out which mechanism was used.
            # Note that password check requires a string (not int or None)
            passcode = self.passcode.data
            if not passcode:
                self.passcode.errors.append(get_message("INVALID_PASSWORD_CODE")[0])
                return False
            passcode = str(passcode)

            ok = False
            for method in cv("US_ENABLED_METHODS"):
                if method == "password" and self.user.password:
                    passcode = _security._password_util.normalize(passcode)
                    if self.user.verify_and_update_password(passcode):
                        ok = True
                        break
                else:
                    if method in totp_secrets and _security._totp_factory.verify_totp(
                        token=passcode,
                        totp_secret=totp_secrets[method],
                        user=self.user,
                        window=cv("US_TOKEN_VALIDITY"),
                    ):
                        ok = True
                        break
            if not ok:
                self.passcode.errors.append(get_message("INVALID_PASSWORD_CODE")[0])
                return False

            self.authn_via = method
            return True
        elif self.submit_send_code.data:
            # Send a code - chosen_method must be valid
            cm = self.chosen_method.data
            if cm not in cv("US_ENABLED_METHODS"):
                self.chosen_method.errors.append(
                    get_message("US_METHOD_NOT_AVAILABLE")[0]
                )
                return False
            if cm not in totp_secrets:
                self.chosen_method.errors.append(
                    get_message("US_METHOD_NOT_AVAILABLE")[0]
                )
                return False
            if cm == "sms" and not self.user.us_phone_number:
                # They need to us-setup!
                self.chosen_method.errors.append(get_message("PHONE_INVALID")[0])
                return False
            return True
        return False  # pragma: no cover


class UnifiedSigninForm(_UnifiedPassCodeForm, NextFormMixin):
    """A unified login form
    For either identity/password or request and enter code.
    """

    identity = StringField(
        get_form_field_label("identity"),
        validators=[Required()],
    )
    remember = BooleanField(get_form_field_label("remember_me"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.remember.default = cv("DEFAULT_REMEMBER_ME")
        self.requires_confirmation = False

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False
        if not _us_common_validate(self):
            return False
        if not super().validate2():
            return False

        # Can't authenticate nor get a code if still required confirmation.
        self.requires_confirmation = requires_confirmation(self.user)
        if self.requires_confirmation:
            self.identity.errors.append(get_message("CONFIRMATION_REQUIRED")[0])
            return False
        return True


class UnifiedVerifyForm(_UnifiedPassCodeForm):
    """Verify authentication.
    This is for freshness 'reauthentication' required.
    """

    def validate(self, **kwargs: t.Any) -> bool:
        self.user = current_user
        if not super().validate(**kwargs):
            return False
        if not super().validate2():
            return False
        return True


class UnifiedSigninSetupForm(Form):
    """Setup form"""

    setup_choices = [
        ("email", get_form_field_label("email_method")),
        (
            "authenticator",
            get_form_field_label("authapp_method"),
        ),
        ("sms", get_form_field_label("sms_method")),
    ]
    chosen_method = RadioField(
        get_form_field_xlate(_("Setup additional sign in option")),
        validate_choice=False,
    )
    delete_choices = [
        ("email", get_form_field_xlate("Delete email option")),
        (
            "authenticator",
            get_form_field_xlate("Delete authenticator option"),
        ),
        ("sms", get_form_field_xlate("Delete SMS option")),
    ]

    delete_method = SelectMultipleField(
        get_form_field_xlate(_("Delete active sign in option")),
        option_widget=CheckboxInput(),
        validate_choice=False,
    )
    phone = TelField(get_form_field_label("phone"))
    submit = SubmitField(get_form_field_label("submit"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False

        if not self.chosen_method.data and not self.delete_method.data:
            self.form_errors.append(get_message("API_ERROR")[0])
            return False
        if self.chosen_method.data:
            if self.chosen_method.data not in cv("US_ENABLED_METHODS"):
                self.chosen_method.errors.append(
                    get_message("US_METHOD_NOT_AVAILABLE")[0]
                )
                return False

            if self.chosen_method.data == "sms":
                msg = _security._phone_util.validate_phone_number(self.phone.data)
                if msg:
                    self.phone.errors.append(msg)
                    return False
                # As an identity attribute - it MUST be unique!
                cphone = _security._phone_util.get_canonical_form(self.phone.data)
                if _datastore.find_user(us_phone_number=cphone):
                    msg = get_message(
                        "IDENTITY_ALREADY_ASSOCIATED",
                        attr="us_phone_number",
                        value=cphone,
                    )[0]
                    self.phone.errors.append(msg)
                    return False
        if self.delete_method.data:
            if not all(
                m in _compute_active_methods(current_user)
                for m in self.delete_method.data
            ):
                self.delete_method.errors.append(
                    get_message("US_METHOD_NOT_AVAILABLE")[0]
                )
                return False

        return True


class UnifiedSigninSetupValidateForm(Form):
    """The unified sign in setup validation form"""

    # These 2 filled in by view
    user: User
    totp_secret: str

    passcode = StringField(
        get_form_field_label("passcode"),
        render_kw={
            "autocomplete": "one-time-code",
            "inputtype": "numeric",
            "pattern": "[0-9]*",
        },
        validators=[Required()],
    )
    submit = SubmitField(get_form_field_label("submitcode"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False

        if not _security._totp_factory.verify_totp(
            token=self.passcode.data,
            totp_secret=self.totp_secret,
            user=self.user,
            window=cv("US_TOKEN_VALIDITY"),
        ):
            self.passcode.errors.append(get_message("INVALID_PASSWORD_CODE")[0])
            return False

        return True


def _send_code_helper(form, send_magic_link):
    # send code
    user = form.user
    method = form.chosen_method.data
    totp_secrets = _datastore.us_get_totp_secrets(user)

    msg = user.us_send_security_token(
        method,
        totp_secret=totp_secrets[method],
        phone_number=getattr(user, "us_phone_number", None),
        send_magic_link=send_magic_link,
    )
    return msg


@anonymous_user_required
@unauth_csrf()
def us_signin_send_code() -> ResponseValue:
    """
    Send code view. POST only.
    This takes an identity (as configured in USER_IDENTITY_ATTRIBUTES)
    and a method request to send a code.
    """
    form = t.cast(UnifiedSigninForm, build_form_from_request("us_signin_form"))
    form.submit_send_code.data = True
    form.submit.data = False

    code_methods = _compute_code_methods()

    if form.validate_on_submit():
        msg = _send_code_helper(form, True)
        if msg:
            form.chosen_method.errors.append(msg)

        if _security._want_json(request):
            # Not authenticated yet - so don't send any user info.
            return base_render_json(
                form, include_user=False, error_status_code=500 if msg else 200
            )

        # Make sure same response as non-setup method below
        do_flash(*generic_message("CODE_HAS_BEEN_SENT", "GENERIC_US_SIGNIN"))

        return _security.render_template(
            cv("US_SIGNIN_TEMPLATE"),
            us_signin_form=form,
            available_methods=cv("US_ENABLED_METHODS"),
            code_methods=code_methods,
            chosen_method=form.chosen_method.data,
            skip_loginmenu=True,
            **_security._run_ctx_processor("us_signin"),
        )
    elif request.method == "POST" and cv("RETURN_GENERIC_RESPONSES"):
        # TODO - this suppresses the error if they don't select ANY send code option.
        rinfo: dict[str, dict[str, str]] = dict(
            identity=dict(), passcode=dict(), chosen_method=dict()
        )
        form_errors_munge(form, rinfo)
        if not _security._want_json(request):
            # Make sure same response as successful code above.
            do_flash(*get_message("GENERIC_US_SIGNIN"))

    # Here on failed validation
    if _security._want_json(request):
        payload = {
            "available_methods": cv("US_ENABLED_METHODS"),
            "code_methods": code_methods,
            "identity_attributes": get_identity_attributes(),
        }
        return base_render_json(form, include_user=False, additional=payload)

    if (
        form.requires_confirmation
        and cv("REQUIRES_CONFIRMATION_ERROR_VIEW")
        and not cv("RETURN_GENERIC_RESPONSES")
    ):
        do_flash(*get_message("CONFIRMATION_REQUIRED"))
        return redirect(get_url(cv("REQUIRES_CONFIRMATION_ERROR_VIEW")))

    return _security.render_template(
        cv("US_SIGNIN_TEMPLATE"),
        us_signin_form=form,
        available_methods=cv("US_ENABLED_METHODS"),
        code_methods=code_methods,
        skip_loginmenu=True,
        **_security._run_ctx_processor("us_signin"),
    )


@auth_required(lambda: cv("API_ENABLED_METHODS"))
def us_verify_send_code() -> ResponseValue:
    """
    Send code during verify. POST only.
    """
    form = t.cast(UnifiedVerifyForm, build_form_from_request("us_verify_form"))
    form.submit_send_code.data = True
    form.submit.data = False

    code_methods = _compute_active_code_methods(current_user)

    if form.validate_on_submit():
        msg = _send_code_helper(form, False)
        if msg:
            form.chosen_method.errors.append(msg)

        if _security._want_json(request):
            # no real reason to send user info?
            return base_render_json(
                form, include_user=False, error_status_code=500 if msg else 200
            )
        if not msg:
            do_flash(*get_message("CODE_HAS_BEEN_SENT"))
        return _security.render_template(
            cv("US_VERIFY_TEMPLATE"),
            us_verify_form=form,
            available_methods=cv("US_ENABLED_METHODS"),
            code_methods=code_methods,
            chosen_method=form.chosen_method.data,
            skip_login_menu=True,
            **_security._run_ctx_processor("us_verify"),
        )

    # Here on failed validation
    if _security._want_json(request):
        return base_render_json(form)

    return _security.render_template(
        cv("US_VERIFY_TEMPLATE"),
        us_verify_form=form,
        available_methods=cv("US_ENABLED_METHODS"),
        code_methods=code_methods,
        skip_login_menu=True,
        **_security._run_ctx_processor("us_verify"),
    )


@unauth_csrf()
def us_signin() -> ResponseValue:
    """
    Unified sign in view.
    This takes an identity (as configured in USER_IDENTITY_ATTRIBUTES)
    and a passcode (password or OTP).

    Allow already authenticated users. For GET this is useful for
    single-page-applications on refresh - session still active but need to
    access user info and csrf-token.
    For POST - redirects to POST_LOGIN_VIEW (forms) or returns 400 (json).
    """

    if is_user_authenticated(current_user) and request.method == "POST":
        # Just redirect current_user to POST_LOGIN_VIEW (or next).
        # While its tempting to try to logout the current user and login the
        # new requested user - that simply doesn't work with CSRF.

        # While this is close to anonymous_user_required - it differs in that
        # it uses get_post_login_redirect which correctly handles 'next'.
        # TODO: consider changing anonymous_user_required to also call
        # get_post_login_redirect - not sure why it never has?
        if _security._want_json(request):
            payload = json_error_response(
                errors=get_message("ANONYMOUS_USER_REQUIRED")[0]
            )
            return _security._render_json(payload, 400, None, None)
        else:
            return redirect(get_post_login_redirect())

    form = t.cast(UnifiedSigninForm, build_form_from_request("us_signin_form"))
    form.submit.data = True
    form.submit_send_code.data = False
    # Clean out any potential old session info - in case of previous
    # aborted 2FA attempt.
    tf_clean_session()

    if form.validate_on_submit():
        # Check if multi-factor is required. Some (this is configurable) don't
        # need 2FA since they ARE multi-factor (such as SMS and authenticator).
        remember_me = form.remember.data if "remember" in form else None
        if form.authn_via in cv("US_MFA_REQUIRED"):
            response = _security.two_factor_plugins.tf_enter(
                form.user,
                remember_me,
                form.authn_via,
                next_loc=propagate_next(request.url, form),
            )
            if response:
                return response
        after_this_request(view_commit)
        login_user(form.user, remember=remember_me, authn_via=[form.authn_via])

        if _security._want_json(request):
            return base_render_json(form, include_auth_token=True)

        return redirect(get_post_login_redirect())
    elif request.method == "POST" and cv("RETURN_GENERIC_RESPONSES"):
        rinfo = dict(
            identity=dict(replace_msg="GENERIC_AUTHN_FAILED"),
            passcode=dict(replace_msg="GENERIC_AUTHN_FAILED"),
        )
        form_errors_munge(form, rinfo)

    # Here on GET or failed POST validate
    code_methods = _compute_code_methods()
    if _security._want_json(request):
        payload = {
            "available_methods": cv("US_ENABLED_METHODS"),
            "code_methods": code_methods,
            "identity_attributes": get_identity_attributes(),
        }
        return base_render_json(form, include_user=False, additional=payload)

    if is_user_authenticated(current_user):
        # Basically a no-op if authenticated - just perform the same
        # post-login redirect as if user just logged in.
        return redirect(get_post_login_redirect())

    # On error - wipe code
    form.passcode.data = None

    if (
        form.requires_confirmation
        and cv("REQUIRES_CONFIRMATION_ERROR_VIEW")
        and not cv("RETURN_GENERIC_RESPONSES")
    ):
        do_flash(*get_message("CONFIRMATION_REQUIRED"))
        return redirect(get_url(cv("REQUIRES_CONFIRMATION_ERROR_VIEW")))

    return _security.render_template(
        cv("US_SIGNIN_TEMPLATE"),
        us_signin_form=form,
        available_methods=cv("US_ENABLED_METHODS"),
        code_methods=code_methods,
        skip_login_menu=True,
        **_security._run_ctx_processor("us_signin"),
    )


@auth_required(lambda: cv("API_ENABLED_METHODS"))
def us_verify() -> ResponseValue:
    """
    Re-authenticate to reset freshness time.
    This is likely the result of a reauthn_handler redirect, which
    will have filled in ?next=xxx - which we want to carefully not lose as we
    go through these steps.
    """
    form = t.cast(UnifiedVerifyForm, build_form_from_request("us_verify_form"))
    form.submit.data = True
    form.submit_send_code.data = False

    code_methods = _compute_active_code_methods(current_user)

    if form.validate_on_submit():
        # verified - so set freshness time.
        session["fs_paa"] = time.time()

        if _security._want_json(request):
            return base_render_json(form, include_auth_token=True)

        do_flash(*get_message("REAUTHENTICATION_SUCCESSFUL"))
        return redirect(get_post_verify_redirect())

    # Here on GET or failed POST validate
    webauthn_available = has_webauthn(current_user, cv("WAN_ALLOW_AS_VERIFY"))
    if _security._want_json(request):
        payload = {
            "available_methods": cv("US_ENABLED_METHODS"),
            "code_methods": code_methods,
            "has_webauthn_verify_credential": webauthn_available,
        }
        return base_render_json(form, additional=payload)

    # On error - wipe code
    form.passcode.data = None
    return _security.render_template(
        cv("US_VERIFY_TEMPLATE"),
        us_verify_form=form,
        code_methods=code_methods,
        skip_login_menu=True,
        has_webauthn_verify_credential=webauthn_available,
        wan_verify_form=build_form("wan_verify_form"),
        **_security._run_ctx_processor("us_verify"),
    )


@anonymous_user_required
def us_verify_link() -> ResponseValue:
    """
    Used to verify a magic email link. GET only
    Since this is just a URL - be careful not to disclose info like
    whether email exists or not.
    """
    fs_uniquifier = request.args.get("id", None)
    code = request.args.get("code", None)
    if not fs_uniquifier or not code:
        m, c = get_message("API_ERROR")
        if cv("REDIRECT_BEHAVIOR") == "spa":
            return redirect(get_url(cv("LOGIN_ERROR_VIEW"), qparams={c: m}))
        do_flash(m, c)
        return redirect(url_for_security("us_signin"))

    user = _datastore.find_user(fs_uniquifier=fs_uniquifier)
    if not user or not user.active:
        if not user:
            m, c = generic_message("USER_DOES_NOT_EXIST", "GENERIC_AUTHN_FAILED")
        else:
            m, c = generic_message("DISABLED_ACCOUNT", "GENERIC_AUTHN_FAILED")
        if cv("REDIRECT_BEHAVIOR") == "spa":
            return redirect(get_url(cv("LOGIN_ERROR_VIEW"), qparams={c: m}))
        do_flash(m, c)
        return redirect(url_for_security("us_signin"))

    totp_secrets = _datastore.us_get_totp_secrets(user)
    if "email" not in totp_secrets or not _security._totp_factory.verify_totp(
        token=code,
        totp_secret=totp_secrets["email"],
        user=user,
        window=cv("US_TOKEN_VALIDITY"),
    ):
        m, c = generic_message("INVALID_CODE", "GENERIC_AUTHN_FAILED")
        if cv("REDIRECT_BEHAVIOR") == "spa":
            return redirect(
                get_url(
                    cv("LOGIN_ERROR_VIEW"),
                    qparams=user.get_redirect_qparams({c: m}),
                )
            )
        do_flash(m, c)
        return redirect(url_for_security("us_signin"))

    tf_setup_methods = []
    if cv("TWO_FACTOR"):
        tf_setup_methods = _security.two_factor_plugins.get_setup_tf_methods(user)
    if (
        cv("TWO_FACTOR")
        and "email" in cv("US_MFA_REQUIRED")
        and (cv("TWO_FACTOR_REQUIRED") or len(tf_setup_methods) > 0)
    ):
        # tf_login doesn't know anything about "spa" etc. In general two-factor
        # isn't quite ready for SPA. So we return an error via a redirect rather
        # than mess up SPA applications. To be clear - this simply doesn't
        # work - using a magic link w/ 2FA - need to use code.
        if cv("REDIRECT_BEHAVIOR") == "spa":
            return redirect(
                get_url(
                    cv("LOGIN_ERROR_VIEW"),
                    qparams=user.get_redirect_qparams({"tf_required": 1}),
                )
            )
        response = _security.two_factor_plugins.tf_enter(
            user, False, "email", next_loc=propagate_next(request.url, None)
        )
        if response:
            return response

    login_user(user, authn_via=["email"])
    after_this_request(view_commit)
    if cv("REDIRECT_BEHAVIOR") == "spa":
        # We do NOT send the authentication token here since the only way to
        # send it would be via a query param and that isn't secure. (logging and
        # possibly HTTP Referer header).
        # This means that this can only work if sessions are active which sort of
        # makes sense - otherwise you need to use /us-signin with a code.
        return redirect(
            get_url(cv("POST_LOGIN_VIEW"), qparams=user.get_redirect_qparams())
        )

    do_flash(*get_message("PASSWORDLESS_LOGIN_SUCCESSFUL"))
    return redirect(get_post_login_redirect())


@auth_required(
    lambda: cv("API_ENABLED_METHODS"),
    within=lambda: cv("FRESHNESS"),
    grace=lambda: cv("FRESHNESS_GRACE_PERIOD"),
)
def us_setup() -> ResponseValue:
    """
    Change unified sign in methods.
    We want to verify the new method - so don't store anything yet in DB
    use a timed signed token to pass along state.
    GET - retrieve current info (json) or form.
    """
    form = t.cast(UnifiedSigninSetupForm, build_form_from_request("us_setup_form"))

    setup_methods = _compute_setup_methods()
    active_methods = _compute_active_methods(current_user)
    form.chosen_method.choices = [
        c for c in form.setup_choices if c[0] not in active_methods
    ]
    form.delete_method.choices = [
        c for c in form.delete_choices if c[0] in active_methods
    ]

    # translate active methods
    if not active_methods:
        active_methods = [None]
    current_methods = _security.i18n_domain.format_list(
        [localize_callback(_setup_methods_xlate[m]) for m in active_methods]
    )
    current_methods_msg = get_message(
        "US_CURRENT_METHODS", method_list=current_methods
    )[0]

    if form.validate_on_submit():
        qrcode_values = dict()
        json_response = dict()
        state_token = None
        delete_method = form.delete_method.data
        add_method = form.chosen_method.data

        if delete_method:
            after_this_request(view_commit)
            for m in delete_method:
                _datastore.us_reset(current_user, m)
            active_methods = _compute_active_methods(current_user)
            if not active_methods:
                active_methods = [None]
            current_methods = _security.i18n_domain.format_list(
                [localize_callback(_setup_methods_xlate[m]) for m in active_methods]
            )

            current_methods_msg = get_message(
                "US_CURRENT_METHODS", method_list=current_methods
            )[0]
            form.chosen_method.choices = [
                c for c in form.setup_choices if c[0] not in active_methods
            ]
            form.delete_method.choices = [
                c for c in form.delete_choices if c[0] in active_methods
            ]
            form.delete_method.data = None
            us_profile_changed.send(
                current_app._get_current_object(),  # type: ignore
                _async_wrapper=current_app.ensure_sync,
                user=current_user,
                methods=delete_method,
                delete=True,
            )

        if add_method:
            # Always generate a totp_secret. We don't set it in the DB until
            # user has successfully validated.
            totp = _security._totp_factory.generate_totp_secret()

            # N.B. totp (totp_secret) is actually encrypted - so it seems safe enough
            # to send it to the user.
            # Only check phone number if SMS (see form validate)
            phone_number = (
                _security._phone_util.get_canonical_form(form.phone.data)
                if add_method == "sms"
                else None
            )
            state = {
                "totp_secret": totp,
                "chosen_method": add_method,
                "phone_number": phone_number,
            }
            msg = current_user.us_send_security_token(
                method=add_method,
                totp_secret=totp,
                phone_number=phone_number,
            )
            if msg:
                # sending didn't work.
                form.chosen_method.errors.append(msg)
                if _security._want_json(request):
                    # Not authenticated yet - so don't send any user info.
                    return base_render_json(
                        form, include_user=False, error_status_code=500 if msg else 400
                    )
                return _security.render_template(
                    cv("US_SETUP_TEMPLATE"),
                    available_methods=cv("US_ENABLED_METHODS"),
                    active_methods=active_methods,
                    current_methods_msg=current_methods_msg,
                    setup_methods=setup_methods,
                    us_setup_form=form,
                    **_security._run_ctx_processor("us_setup"),
                )

            state_token = _security.us_setup_serializer.dumps(state)
            json_response = dict(
                chosen_method=form.chosen_method.data,
                phone=phone_number,
                state=state_token,
            )

            if form.chosen_method.data == "authenticator":
                authr_setup_values = _security._totp_factory.fetch_setup_values(
                    totp, current_user
                )

                # Add all the values used in qrcode to json response
                json_response["authr_key"] = authr_setup_values["key"]
                json_response["authr_username"] = authr_setup_values["username"]
                json_response["authr_issuer"] = authr_setup_values["issuer"]

                qrcode_values = dict(
                    authr_qrcode=authr_setup_values["image"],
                    authr_key=authr_setup_values["key"],
                    authr_username=authr_setup_values["username"],
                    authr_issuer=authr_setup_values["issuer"],
                )

        if _security._want_json(request):
            return base_render_json(form, include_user=False, additional=json_response)
        form.delete_method.data = None
        return _security.render_template(
            cv("US_SETUP_TEMPLATE"),
            available_methods=cv("US_ENABLED_METHODS"),
            active_methods=active_methods,
            current_methods_msg=current_methods_msg,
            setup_methods=setup_methods,
            code_sent=form.chosen_method.data in _compute_code_methods(),
            chosen_method=form.chosen_method.data,
            us_setup_form=form,
            us_setup_validate_form=build_form("us_setup_validate_form"),
            **qrcode_values,
            state=state_token,
            **_security._run_ctx_processor("us_setup"),
        )

    # Get here on initial new setup (GET)
    # Or failure of POST
    if _security._want_json(request):
        payload = {
            "identity_attributes": get_identity_attributes(),
            "available_methods": cv("US_ENABLED_METHODS"),
            "active_methods": active_methods,
            "setup_methods": setup_methods,
            "phone": current_user.us_phone_number,
        }
        return base_render_json(form, include_user=False, additional=payload)

    # Show user existing phone number
    form.phone.data = current_user.us_phone_number
    form.chosen_method.data = None
    form.delete_method.data = None
    return _security.render_template(
        cv("US_SETUP_TEMPLATE"),
        available_methods=cv("US_ENABLED_METHODS"),
        active_methods=active_methods,
        current_methods_msg=current_methods_msg,
        setup_methods=setup_methods,
        us_setup_form=form,
        **_security._run_ctx_processor("us_setup"),
    )


@auth_required(lambda: cv("API_ENABLED_METHODS"))
def us_setup_validate(token: str) -> ResponseValue:
    """
    Validate new setup.
    The token is the state variable which is signed and timed
    and contains all the state that once confirmed will be stored in the user record.
    """
    form = t.cast(
        UnifiedSigninSetupValidateForm,
        build_form_from_request("us_setup_validate_form"),
    )

    expired, invalid, state = check_and_get_token_status(
        token, "us_setup", get_within_delta("US_SETUP_WITHIN")
    )
    if invalid:
        m, c = get_message("API_ERROR")
    if expired:
        m, c = get_message("US_SETUP_EXPIRED", within=cv("US_SETUP_WITHIN"))
    if invalid or expired:
        if _security._want_json(request):
            form.form_errors.append(m)
            return base_render_json(form, include_user=False)
        do_flash(m, c)
        return redirect(url_for_security("us_setup"))

    form.totp_secret = state["totp_secret"]
    form.user = current_user

    if form.validate_on_submit():
        after_this_request(view_commit)
        method = state["chosen_method"]
        phone = state["phone_number"] if method == "sms" else None
        _datastore.us_set(current_user, method, state["totp_secret"], phone)

        us_profile_changed.send(
            current_app._get_current_object(),  # type: ignore
            _async_wrapper=current_app.ensure_sync,
            user=current_user,
            methods=[method],
            delete=False,
        )
        if _security._want_json(request):
            return base_render_json(
                form,
                include_user=False,
                additional=dict(
                    chosen_method=method, phone=current_user.us_phone_number
                ),
            )
        else:
            do_flash(*get_message("US_SETUP_SUCCESSFUL"))
            return redirect(get_url(cv("US_POST_SETUP_VIEW")))

    # Code not correct/outdated.
    if _security._want_json(request):
        return base_render_json(form, include_user=False)
    m, c = get_message("INVALID_PASSWORD_CODE")
    do_flash(m, c)
    return redirect(url_for_security("us_setup"))


def us_send_security_token(
    user, method, totp_secret, phone_number, send_magic_link=False
):
    """Generate and send the security code.

    :param user: The user to send the code to
    :param method: The method in which the code will be sent
    :param totp_secret: the unique shared secret of the user
    :param phone_number: If 'sms' phone number to send to
    :param send_magic_link: If true a magic link that can be clicked on will be sent.
            This shouldn't be sent during a setup.

    There is no return value - it is assumed that exceptions are thrown by underlying
    methods that callers can catch.

    Flask-Security code should NOT call this directly -
    call :meth:`.UserMixin.us_send_security_token`

    .. versionadded:: 3.4.0
    """
    code = _security._totp_factory.generate_totp_password(totp_secret)

    if method == "email":
        login_link = None
        if send_magic_link:
            login_link = url_for_security(
                "us_verify_link", id=str(user.fs_uniquifier), code=code, _external=True
            )
        send_mail(
            cv("US_EMAIL_SUBJECT"),
            user.email,
            "us_instructions",
            user=user,
            username=user.calc_username(),
            token=code,  # deprecated
            login_token=code,
            login_link=login_link,
        )
    elif method == "sms":
        m, c = get_message("USE_CODE", code=code)
        from_number = cv("SMS_SERVICE_CONFIG")["PHONE_NUMBER"]
        to_number = phone_number
        sms_sender = SmsSenderFactory.createSender(cv("SMS_SERVICE"))
        sms_sender.send_sms(from_number=from_number, to_number=to_number, msg=m)

    elif method == "authenticator" or method == "password":
        # tokens are generated automatically with authenticator apps
        # and passwords are well passwords
        # Still go ahead and notify signal receivers that they requested it.
        code = None
    us_security_token_sent.send(
        current_app._get_current_object(),
        _async_wrapper=current_app.ensure_sync,
        user=user,
        method=method,
        token=code,
        login_token=code,
        phone_number=phone_number,
        send_magic_link=send_magic_link,
    )
