"""
    flask_security.unified_signin
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security Unified Signin module

    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    This implements a unified sign in endpoint - allowing
    authentication via identity and passcode - where identity is configured
    via SECURITY_USER_IDENTITY_ATTRIBUTES, and allowable passcodes are either a
    password or one of US_ENABLED_METHODS.

    Finish up:
    - we should be able to add a phone number as part of setup even w/o any METHODS -
      i.e. to allow login with any identity (phone) and a password.

    Consider/Questions:
    - Allow registering/confirming with just a phone number - this likely would require
      a new register/confirm endpoint in order to implement verification.
    - Right now ChangePassword won't work - it requires an existing password - so
      if the user doesn't have one - can't change it. However ForgotPassword will in
      fact allow the user to add a password. Is that sufficient?
    - Any reason to support 'next' in form? xx?next=yyy works fine.
    - separate code validation times for SMS, email, authenticator?
    - token versus code versus passcode? Confusing terminology.

"""

import time

from flask import current_app as app
from flask import after_this_request, request, session
from flask_login import current_user
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy
from wtforms import BooleanField, RadioField, StringField, SubmitField, validators

from .confirmable import requires_confirmation
from .decorators import anonymous_user_required, auth_required, unauth_csrf
from .forms import Form, Required, get_form_field_label
from .quart_compat import get_quart_status
from .signals import us_profile_changed, us_security_token_sent
from .twofactor import (
    is_tf_setup,
    tf_login,
    tf_verify_validility_token,
)
from .utils import (
    _,
    SmsSenderFactory,
    base_render_json,
    check_and_get_token_status,
    config_value,
    do_flash,
    find_user,
    get_identity_attributes,
    get_post_login_redirect,
    get_post_verify_redirect,
    get_message,
    get_url,
    get_within_delta,
    json_error_response,
    login_user,
    propagate_next,
    send_mail,
    suppress_form_csrf,
    url_for_security,
    view_commit,
)

# Convenient references
_security = LocalProxy(lambda: app.extensions["security"])
_datastore = LocalProxy(lambda: _security.datastore)

if get_quart_status():  # pragma: no cover
    from quart import redirect


else:
    from flask import redirect


def _compute_code_methods():
    # Return list of methods that actually send codes
    return list(set(config_value("US_ENABLED_METHODS")) - {"password", "authenticator"})


def _compute_setup_methods():
    # Return list of methods that require setup
    return list(set(config_value("US_ENABLED_METHODS")) - {"password"})


def _compute_active_methods(user):
    # Compute methods already setup. The only oddity is that 'email'
    # can be 'auto-setup' - so include that.
    active_methods = set(config_value("US_ENABLED_METHODS")) & set(
        _datastore.us_get_totp_secrets(user).keys()
    )
    if "email" in config_value("US_ENABLED_METHODS"):
        active_methods |= {"email"}
    return list(active_methods)


def _us_common_validate(form):
    # Be aware - this has side effect on the form - it will fill in
    # the form.user

    # Validate identity - we go in order to figure out which user attribute the
    # request gave us. Note that we give up on the first 'match' even if that
    # doesn't yield a user. Why?
    form.user = find_user(form.identity.data)
    if not form.user:
        form.identity.errors.append(get_message("US_SPECIFY_IDENTITY")[0])
        return False
    if not form.user.is_active:
        form.identity.errors.append(get_message("DISABLED_ACCOUNT")[0])
        return False
    return True


class _UnifiedPassCodeForm(Form):
    """Common form for signin and verify/reauthenticate."""

    user = None
    authn_via = None

    passcode = StringField(
        get_form_field_label("passcode"),
        render_kw={"placeholder": _("Code or Password")},
    )
    submit = SubmitField(get_form_field_label("submit"))

    chosen_method = RadioField(
        _("Available Methods"),
        choices=[("email", _("Via email")), ("sms", _("Via SMS"))],
        validators=[validators.Optional()],
    )
    submit_send_code = SubmitField(get_form_field_label("sendcode"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self):
        if not super().validate():
            return False
        if not self.user:
            # This is sign-in case.
            if not _us_common_validate(self):
                return False

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
            for method in config_value("US_ENABLED_METHODS"):
                if method == "password":
                    passcode = _security._password_util.normalize(passcode)
                    if self.user.verify_and_update_password(passcode):
                        ok = True
                        break
                else:
                    if method in totp_secrets and _security._totp_factory.verify_totp(
                        token=passcode,
                        totp_secret=totp_secrets[method],
                        user=self.user,
                        window=config_value("US_TOKEN_VALIDITY"),
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
            if cm not in config_value("US_ENABLED_METHODS"):
                self.chosen_method.errors.append(
                    get_message("US_METHOD_NOT_AVAILABLE")[0]
                )
                return False
            # Don't require 'email' to be setup since in the case of no password
            # we have to rely on the 'confirmation' email as verification.
            # In send_code_helper, we will setup the totp_secret for email on the fly.
            if cm != "email" and cm not in totp_secrets:
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


class UnifiedSigninForm(_UnifiedPassCodeForm):
    """A unified login form
    For either identity/password or request and enter code.
    """

    user = None

    identity = StringField(
        get_form_field_label("identity"),
        validators=[Required()],
    )
    remember = BooleanField(get_form_field_label("remember_me"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.remember.default = config_value("DEFAULT_REMEMBER_ME")
        self.requires_confirmation = False

    def validate(self):
        self.user = None
        if not super().validate():
            return False

        if self.submit.data:
            # This is login
            # Only check this once authenticated to not give away info
            self.requires_confirmation = requires_confirmation(self.user)
            if self.requires_confirmation:
                self.identity.errors.append(get_message("CONFIRMATION_REQUIRED")[0])
                return False
        return True


class UnifiedVerifyForm(_UnifiedPassCodeForm):
    """Verify authentication.
    This is for freshness 'reauthentication' required.
    """

    user = None

    def validate(self):
        self.user = current_user
        if not super().validate():
            return False
        return True


class UnifiedSigninSetupForm(Form):
    """ Setup form """

    chosen_method = RadioField(
        _("Available Methods"),
        choices=[
            ("email", _("Set up using email")),
            (
                "authenticator",
                _("Set up using an authenticator app (e.g. google, lastpass, authy)"),
            ),
            ("sms", _("Set up using SMS")),
        ],
    )
    phone = StringField(get_form_field_label("phone"))
    submit = SubmitField(get_form_field_label("submit"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self):
        if not super().validate():
            return False
        if self.chosen_method.data not in config_value("US_ENABLED_METHODS"):
            self.chosen_method.errors.append(get_message("US_METHOD_NOT_AVAILABLE")[0])
            return False

        if self.chosen_method.data == "sms":
            msg = _security._phone_util.validate_phone_number(self.phone.data)
            if msg:
                self.phone.errors.append(msg)
                return False

        return True


class UnifiedSigninSetupValidateForm(Form):
    """The unified sign in setup validation form """

    # These 2 filled in by view
    user = None
    totp_secret = None

    passcode = StringField(get_form_field_label("passcode"), validators=[Required()])
    submit = SubmitField(get_form_field_label("submitcode"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self):
        if not super().validate():
            return False

        if not _security._totp_factory.verify_totp(
            token=self.passcode.data,
            totp_secret=self.totp_secret,
            user=self.user,
            window=config_value("US_TOKEN_VALIDITY"),
        ):
            self.passcode.errors.append(get_message("INVALID_PASSWORD_CODE")[0])
            return False

        return True


def _send_code_helper(form):
    # send code
    user = form.user
    method = form.chosen_method.data
    totp_secrets = _datastore.us_get_totp_secrets(user)
    # We 'auto-setup' email since in the case of no password the normal us-setup
    # mechanisms of course don't work. We rely on the fact that the user went
    # through the 'confirmation' process to validate the email.
    if method == "email" and method not in totp_secrets:
        after_this_request(view_commit)
        totp_secrets[method] = _security._totp_factory.generate_totp_secret()
        _datastore.us_put_totp_secrets(user, totp_secrets)

    msg = user.us_send_security_token(
        method,
        totp_secret=totp_secrets[method],
        phone_number=getattr(user, "us_phone_number", None),
        send_magic_link=True,
    )
    code_sent = True
    if msg:
        # send code didn't work
        code_sent = False
        form.chosen_method.errors.append(msg)
    return code_sent, msg


@anonymous_user_required
@unauth_csrf(fall_through=True)
def us_signin_send_code():
    """
    Send code view.
    This takes an identity (as configured in USER_IDENTITY_ATTRIBUTES)
    and a method request to send a code.
    """
    form_class = _security.us_signin_form

    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())
    form.submit_send_code.data = True

    code_methods = _compute_code_methods()

    if form.validate_on_submit():
        code_sent, msg = _send_code_helper(form)
        if _security._want_json(request):
            # Not authenticated yet - so don't send any user info.
            return base_render_json(
                form, include_user=False, error_status_code=500 if msg else 400
            )

        return _security.render_template(
            config_value("US_SIGNIN_TEMPLATE"),
            us_signin_form=form,
            available_methods=config_value("US_ENABLED_METHODS"),
            code_methods=code_methods,
            chosen_method=form.chosen_method.data,
            code_sent=code_sent,
            skip_loginmenu=True,
            **_security._run_ctx_processor("us_signin")
        )

    # Here on GET or failed validation
    if _security._want_json(request):
        payload = {
            "available_methods": config_value("US_ENABLED_METHODS"),
            "code_methods": code_methods,
            "identity_attributes": get_identity_attributes(),
        }
        return base_render_json(form, include_user=False, additional=payload)

    return _security.render_template(
        config_value("US_SIGNIN_TEMPLATE"),
        us_signin_form=form,
        available_methods=config_value("US_ENABLED_METHODS"),
        code_methods=code_methods,
        skip_loginmenu=True,
        **_security._run_ctx_processor("us_signin")
    )


@auth_required(lambda: config_value("API_ENABLED_METHODS"))
def us_verify_send_code():
    """
    Send code during verify.
    """
    form_class = _security.us_verify_form

    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())
    form.submit_send_code.data = True

    code_methods = _compute_code_methods()

    if form.validate_on_submit():
        code_sent, msg = _send_code_helper(form)
        if _security._want_json(request):
            # Not authenticated yet - so don't send any user info.
            return base_render_json(
                form, include_user=False, error_status_code=500 if msg else 400
            )

        return _security.render_template(
            config_value("US_VERIFY_TEMPLATE"),
            us_verify_form=form,
            available_methods=config_value("US_ENABLED_METHODS"),
            code_methods=code_methods,
            chosen_method=form.chosen_method.data,
            code_sent=code_sent,
            skip_login_menu=True,
            send_code_to=get_url(
                _security.us_verify_send_code_url,
                qparams={"next": propagate_next(request.url)},
            ),
            **_security._run_ctx_processor("us_verify")
        )

    # Here on GET or failed validation
    if _security._want_json(request):
        payload = {
            "available_methods": config_value("US_ENABLED_METHODS"),
            "code_methods": code_methods,
        }
        return base_render_json(form, additional=payload)

    return _security.render_template(
        config_value("US_VERIFY_TEMPLATE"),
        us_verify_form=form,
        available_methods=config_value("US_ENABLED_METHODS"),
        code_methods=code_methods,
        skip_login_menu=True,
        send_code_to=get_url(
            _security.us_verify_send_code_url,
            qparams={"next": propagate_next(request.url)},
        ),
        **_security._run_ctx_processor("us_verify")
    )


@unauth_csrf(fall_through=True)
def us_signin():
    """
    Unified sign in view.
    This takes an identity (as configured in USER_IDENTITY_ATTRIBUTES)
    and a passcode (password or OTP).

    Allow already authenticated users. For GET this is useful for
    single-page-applications on refresh - session still active but need to
    access user info and csrf-token.
    For POST - redirects to POST_LOGIN_VIEW (forms) or returns 400 (json).
    """

    if current_user.is_authenticated and request.method == "POST":
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

    form_class = _security.us_signin_form

    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())
    form.submit.data = True

    if form.validate_on_submit():

        # Require multi-factor is it is enabled, and the method
        # we authenticated with requires it and either user has requested MFA or it is
        # required.
        remember_me = form.remember.data if "remember" in form else None
        if config_value("TWO_FACTOR") and form.authn_via in config_value(
            "US_MFA_REQUIRED"
        ):
            if request.is_json and request.content_length:
                tf_validity_token = request.get_json().get("tf_validity_token", None)
            else:
                tf_validity_token = request.cookies.get("tf_validity", default=None)

            tf_validity_token_is_valid = tf_verify_validility_token(
                tf_validity_token, form.user.fs_uniquifier
            )
            if config_value("TWO_FACTOR_REQUIRED") or is_tf_setup(form.user):
                if config_value("TWO_FACTOR_ALWAYS_VALIDATE") or (
                    not tf_validity_token_is_valid
                ):

                    return tf_login(
                        form.user,
                        remember=remember_me,
                        primary_authn_via=form.authn_via,
                    )

        after_this_request(view_commit)
        login_user(form.user, remember=remember_me, authn_via=[form.authn_via])

        if _security._want_json(request):
            return base_render_json(form, include_auth_token=True)

        return redirect(get_post_login_redirect())

    # Here on GET or failed POST validate
    code_methods = _compute_code_methods()
    if _security._want_json(request):
        payload = {
            "available_methods": config_value("US_ENABLED_METHODS"),
            "code_methods": code_methods,
            "identity_attributes": get_identity_attributes(),
        }
        return base_render_json(form, include_user=False, additional=payload)

    if current_user.is_authenticated:
        # Basically a no-op if authenticated - just perform the same
        # post-login redirect as if user just logged in.
        return redirect(get_post_login_redirect())

    # On error - wipe code
    form.passcode.data = None

    if form.requires_confirmation and _security.requires_confirmation_error_view:
        do_flash(*get_message("CONFIRMATION_REQUIRED"))
        return redirect(get_url(_security.requires_confirmation_error_view))

    return _security.render_template(
        config_value("US_SIGNIN_TEMPLATE"),
        us_signin_form=form,
        available_methods=config_value("US_ENABLED_METHODS"),
        code_methods=code_methods,
        skip_login_menu=True,
        **_security._run_ctx_processor("us_signin")
    )


@auth_required(lambda: config_value("API_ENABLED_METHODS"))
def us_verify():
    """
    Re-authenticate to reset freshness time.
    This is likely the result of a reauthn_handler redirect, which
    will have filled in ?next=xxx - which we want to carefully not lose as we
    go through these steps.
    """
    form_class = _security.us_verify_form

    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())
    form.submit.data = True

    code_methods = _compute_code_methods()

    if form.validate_on_submit():
        # verified - so set freshness time.
        session["fs_paa"] = time.time()

        if _security._want_json(request):
            return base_render_json(form, include_auth_token=True)

        do_flash(*get_message("REAUTHENTICATION_SUCCESSFUL"))
        return redirect(get_post_verify_redirect())

    # Here on GET or failed POST validate
    if _security._want_json(request):
        payload = {
            "available_methods": config_value("US_ENABLED_METHODS"),
            "code_methods": code_methods,
        }
        return base_render_json(form, additional=payload)

    # On error - wipe code
    form.passcode.data = None
    return _security.render_template(
        config_value("US_VERIFY_TEMPLATE"),
        us_verify_form=form,
        code_methods=code_methods,
        skip_login_menu=True,
        send_code_to=get_url(
            _security.us_verify_send_code_url,
            qparams={"next": propagate_next(request.url)},
        ),
        **_security._run_ctx_processor("us_verify")
    )


@anonymous_user_required
def us_verify_link():
    """
    Used to verify a magic email link. GET only
    """
    if not all(v in request.args for v in ["email", "code"]):
        m, c = get_message("API_ERROR")
        if _security.redirect_behavior == "spa":
            return redirect(get_url(_security.login_error_view, qparams={c: m}))
        do_flash(m, c)
        return redirect(url_for_security("us_signin"))

    user = _datastore.find_user(email=request.args.get("email"))
    if not user or not user.active:
        if not user:
            m, c = get_message("USER_DOES_NOT_EXIST")
        else:
            m, c = get_message("DISABLED_ACCOUNT")
        if _security.redirect_behavior == "spa":
            return redirect(get_url(_security.login_error_view, qparams={c: m}))
        do_flash(m, c)
        return redirect(url_for_security("us_signin"))

    totp_secrets = _datastore.us_get_totp_secrets(user)
    if "email" not in totp_secrets or not _security._totp_factory.verify_totp(
        token=request.args.get("code"),
        totp_secret=totp_secrets["email"],
        user=user,
        window=config_value("US_TOKEN_VALIDITY"),
    ):
        m, c = get_message("INVALID_CODE")
        if _security.redirect_behavior == "spa":
            return redirect(
                get_url(
                    _security.login_error_view,
                    qparams=user.get_redirect_qparams({c: m}),
                )
            )
        do_flash(m, c)
        return redirect(url_for_security("us_signin"))

    if (
        config_value("TWO_FACTOR")
        and "email" in config_value("US_MFA_REQUIRED")
        and (config_value("TWO_FACTOR_REQUIRED") or is_tf_setup(user))
    ):
        # tf_login doesn't know anything about "spa" etc. In general two-factor
        # isn't quite ready for SPA. So we return an error via a redirect rather
        # than mess up SPA applications. To be clear - this simply doesn't
        # work - using a magic link w/ 2FA - need to use code.
        if _security.redirect_behavior == "spa":
            return redirect(
                get_url(
                    _security.login_error_view,
                    qparams=user.get_redirect_qparams({"tf_required": 1}),
                )
            )
        return tf_login(user, primary_authn_via="email")

    login_user(user, authn_via=["email"])
    after_this_request(view_commit)
    if _security.redirect_behavior == "spa":
        # We do NOT send the authentication token here since the only way to
        # send it would be via a query param and that isn't secure. (logging and
        # possibly HTTP Referer header).
        # This means that this can only work if sessions are active which sort of
        # makes sense - otherwise you need to use /us-signin with a code.
        return redirect(
            get_url(_security.post_login_view, qparams=user.get_redirect_qparams())
        )

    do_flash(*get_message("PASSWORDLESS_LOGIN_SUCCESSFUL"))
    return redirect(get_post_login_redirect())


@auth_required(
    lambda: config_value("API_ENABLED_METHODS"),
    within=lambda: config_value("FRESHNESS"),
    grace=lambda: config_value("FRESHNESS_GRACE_PERIOD"),
)
def us_setup():
    """
    Change unified sign in methods.
    We want to verify the new method - so don't store anything yet in DB
    use a timed signed token to pass along state.
    GET - retrieve current info (json) or form.
    """
    form_class = _security.us_setup_form

    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    setup_methods = _compute_setup_methods()
    active_methods = _compute_active_methods(current_user)

    if form.validate_on_submit():
        method = form.chosen_method.data
        # Always generate a totp_secret. We don't set it in the DB until
        # user has successfully validated.
        totp = _security._totp_factory.generate_totp_secret()

        # N.B. totp (totp_secret) is actually encrypted - so it seems safe enough
        # to send it to the user.
        # Only check phone number if SMS (see form validate)
        phone_number = (
            _security._phone_util.get_canonical_form(form.phone.data)
            if method == "sms"
            else None
        )
        state = {
            "totp_secret": totp,
            "chosen_method": method,
            "phone_number": phone_number,
        }
        msg = current_user.us_send_security_token(
            method=method,
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
                config_value("US_SETUP_TEMPLATE"),
                available_methods=config_value("US_ENABLED_METHODS"),
                active_methods=active_methods,
                setup_methods=setup_methods,
                us_setup_form=form,
                **_security._run_ctx_processor("us_setup")
            )

        state_token = _security.us_setup_serializer.dumps(state)
        json_response = dict(
            chosen_method=form.chosen_method.data,
            phone=phone_number,
            state=state_token,
        )
        qrcode_values = dict()
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
        return _security.render_template(
            config_value("US_SETUP_TEMPLATE"),
            available_methods=config_value("US_ENABLED_METHODS"),
            active_methods=active_methods,
            setup_methods=setup_methods,
            code_sent=form.chosen_method.data in _compute_code_methods(),
            chosen_method=form.chosen_method.data,
            us_setup_form=form,
            us_setup_validate_form=_security.us_setup_validate_form(),
            **qrcode_values,
            state=state_token,
            **_security._run_ctx_processor("us_setup")
        )

    # Get here on initial new setup (GET)
    # Or failure of POST
    if _security._want_json(request):
        payload = {
            "identity_attributes": get_identity_attributes(),
            "available_methods": config_value("US_ENABLED_METHODS"),
            "active_methods": active_methods,
            "setup_methods": setup_methods,
            "phone": current_user.us_phone_number,
        }
        return base_render_json(form, include_user=False, additional=payload)

    # Show user existing phone number
    form.phone.data = current_user.us_phone_number
    return _security.render_template(
        config_value("US_SETUP_TEMPLATE"),
        available_methods=config_value("US_ENABLED_METHODS"),
        active_methods=active_methods,
        setup_methods=setup_methods,
        us_setup_form=form,
        **_security._run_ctx_processor("us_setup")
    )


@auth_required(lambda: config_value("API_ENABLED_METHODS"))
def us_setup_validate(token):
    """
    Validate new setup.
    The token is the state variable which is signed and timed
    and contains all the state that once confirmed will be stored in the user record.
    """

    form_class = _security.us_setup_validate_form

    if request.is_json:
        form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    expired, invalid, state = check_and_get_token_status(
        token, "us_setup", get_within_delta("US_SETUP_WITHIN")
    )
    if invalid:
        m, c = get_message("API_ERROR")
    if expired:
        m, c = get_message("US_SETUP_EXPIRED", within=config_value("US_SETUP_WITHIN"))
    if invalid or expired:
        if _security._want_json(request):
            payload = json_error_response(errors=m)
            return _security._render_json(payload, 400, None, None)
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
            app._get_current_object(), user=current_user, method=method
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
            return redirect(
                get_url(_security.us_post_setup_view)
                or get_url(_security.post_login_view)
            )

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
    token = _security._totp_factory.generate_totp_password(totp_secret)

    if method == "email":
        login_link = None
        if send_magic_link:
            login_link = url_for_security(
                "us_verify_link", email=user.email, code=token, _external=True
            )
        send_mail(
            config_value("US_EMAIL_SUBJECT"),
            user.email,
            "us_instructions",
            user=user,
            username=user.calc_username(),
            token=token,
            login_link=login_link,
        )
    elif method == "sms":
        m, c = get_message("USE_CODE", code=token)
        from_number = config_value("SMS_SERVICE_CONFIG")["PHONE_NUMBER"]
        to_number = phone_number
        sms_sender = SmsSenderFactory.createSender(config_value("SMS_SERVICE"))
        sms_sender.send_sms(from_number=from_number, to_number=to_number, msg=m)

    elif method == "authenticator" or method == "password":
        # tokens are generated automatically with authenticator apps
        # and passwords are well passwords
        # Still go ahead and notify signal receivers that they requested it.
        token = None
    us_security_token_sent.send(
        app._get_current_object(),
        user=user,
        method=method,
        token=token,
        phone_number=phone_number,
        send_magic_link=send_magic_link,
    )
