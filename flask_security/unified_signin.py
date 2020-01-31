# -*- coding: utf-8 -*-
"""
    flask_security.unified_signin
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security Unified signin module

    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    This implements a unified sign in endpoint - allowing
    authentication via identity and passcode - where identity is configured
    via SECURITY_USER_IDENTITY_ATTRIBUTES, and allowable passcodes are either a
    password or one of US_ENABLED_METHODS.

    Finish up:
    - 2FA? since this is now a universal login - probably yes.
    - setup should probably require a 'fresh' authentication - as 2FA does.
    - should we support a way that /logout redirects to us-signin rather than /login?
    - we should be able to add a phone number as part of setup even w/o any METHODS -
      i.e. to allow login with any identity (phone) and a password.
    - openapi.yaml
    - add new example?
    - add username as last IDENTITY_MAPPING and allow anything...?? or just in example?

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

import sys

from flask import current_app as app
from flask import abort, after_this_request, redirect, request
from flask_login import current_user
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy
from wtforms import BooleanField, RadioField, StringField, SubmitField, validators

from .confirmable import requires_confirmation
from .decorators import anonymous_user_required, auth_required, unauth_csrf
from .forms import Form, Required, get_form_field_label
from .quart_compat import get_quart_status
from .signals import us_profile_changed, us_security_token_sent
from .utils import (
    _,
    SmsSenderFactory,
    base_render_json,
    check_and_get_token_status,
    config_value,
    do_flash,
    get_post_login_redirect,
    get_message,
    get_url,
    get_within_delta,
    json_error_response,
    login_user,
    suppress_form_csrf,
    url_for_security,
)

# Convenient references
_security = LocalProxy(lambda: app.extensions["security"])
_datastore = LocalProxy(lambda: _security.datastore)


PY3 = sys.version_info[0] == 3
if PY3 and get_quart_status():  # pragma: no cover
    from .async_compat import _commit  # noqa: F401
else:

    def _commit(response=None):
        _datastore.commit()
        return response


def _us_common_validate(form):
    # Be aware - this has side effect on the form - it will fill in
    # the form.user

    # Validate identity - we go in order to figure out which user attribute the
    # request gave us. Note that we give up on the first 'match' even if that
    # doesn't yield a user. Why?
    for mapping in config_value("USER_IDENTITY_MAPPINGS"):
        for ua, mapper in mapping.items():
            # Make sure we don't validate on a column that application
            # hasn't specifically configured as a unique/identity column
            # In other words - might have a phone number for 2FA or unified
            # but don't want the user to be able to use that as primary identity
            if ua in config_value("USER_IDENTITY_ATTRIBUTES"):
                # Allow mapper to alter (coerce) to type DB requires
                idata = mapper(form.identity.data)
                if idata is not None:
                    form.user = _datastore.find_user(**{ua: idata})

    if not form.user:
        form.identity.errors.append(get_message("US_SPECIFY_IDENTITY")[0])
        return False
    if not form.user.is_active:
        form.identity.errors.append(get_message("DISABLED_ACCOUNT")[0])
        return False
    return True


class UnifiedSigninForm(Form):
    """ A unified login form
    For either identity/password or request and enter code.
    """

    user = None

    identity = StringField(
        get_form_field_label("identity"),
        validators=[Required()],
        render_kw={"placeholder": _("email, phone, username")},
    )

    passcode = StringField(
        get_form_field_label("passcode"),
        render_kw={"placeholder": _("Code or Password")},
    )
    remember = BooleanField(get_form_field_label("remember_me"))
    submit = SubmitField(get_form_field_label("signin"))

    chosen_method = RadioField(
        _("Available Methods"),
        choices=[("email", _("Via email")), ("sms", _("Via SMS"))],
        validators=[validators.Optional()],
    )
    submit_send_code = SubmitField(get_form_field_label("sendcode"))

    def __init__(self, *args, **kwargs):
        super(UnifiedSigninForm, self).__init__(*args, **kwargs)
        self.remember.default = config_value("DEFAULT_REMEMBER_ME")

    def validate(self):
        if not super(UnifiedSigninForm, self).validate():
            return False

        # For either - require a valid identity
        if not _us_common_validate(self):
            return False

        if self.submit.data:
            # This is login - verify passcode/password
            if not self.user.us_totp_secret or not _security._totp_factory.verify_totp(
                token=self.passcode.data,
                totp_secret=self.user.us_totp_secret,
                user=self.user,
                window=config_value("US_TOKEN_VALIDITY"),
            ):
                # That didn't work - maybe it's just a password
                if "password" not in config_value(
                    "US_ENABLED_METHODS"
                ) or not self.user.verify_and_update_password(self.passcode.data):
                    self.passcode.errors.append(get_message("INVALID_PASSWORD")[0])
                    return False

            # Only check this once authenticated to not give away info
            if requires_confirmation(self.user):
                self.identity.errors.append(get_message("CONFIRMATION_REQUIRED")[0])
                return False
            return True
        elif self.submit_send_code.data:
            # Send a code - identity and chosen_method must be valid
            # Note: we don't check for NOT CONFIRMED account here and go
            # ahead and send a code - but above we check and won't let them sign in.
            # The idea is to not expose info if not authenticated
            if self.chosen_method.data not in config_value("US_ENABLED_METHODS"):
                self.chosen_method.errors.append(
                    get_message("US_METHOD_NOT_AVAILABLE")[0]
                )
                return False
            if self.chosen_method.data == "sms" and not self.user.us_phone_number:
                # They need to us-setup!
                self.chosen_method.errors.append(get_message("PHONE_INVALID")[0])
                return False
            return True
        return False  # pragma: no cover


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

    # By default we don't create a new totp_secret since that would invalidate
    # any authenticator setup. Allow user to request a reset.
    new_totp_secret = BooleanField(get_form_field_label("new_totp_secret"))
    submit = SubmitField(get_form_field_label("submit"))

    def __init__(self, *args, **kwargs):
        super(UnifiedSigninSetupForm, self).__init__(*args, **kwargs)

    def validate(self):
        if not super(UnifiedSigninSetupForm, self).validate():
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


class UnifiedSigninSetupVerifyForm(Form):
    """The unified sign in setup validation form """

    # These 2 filled in by view
    user = None
    totp_secret = None

    code = StringField(get_form_field_label("code"), validators=[Required()])
    submit = SubmitField(get_form_field_label("submitcode"))

    def __init__(self, *args, **kwargs):
        super(UnifiedSigninSetupVerifyForm, self).__init__(*args, **kwargs)

    def validate(self):
        if not super(UnifiedSigninSetupVerifyForm, self).validate():
            return False

        if not _security._totp_factory.verify_totp(
            token=self.code.data,
            totp_secret=self.totp_secret,
            user=self.user,
            window=config_value("US_TOKEN_VALIDITY"),
        ):
            self.code.errors.append(get_message("INVALID_CODE")[0])
            return False

        return True


@anonymous_user_required
@unauth_csrf(fall_through=True)
def us_send_code():
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

    if form.validate_on_submit():
        # send code
        user = form.user
        if not user.us_totp_secret:
            after_this_request(_commit)
            user.us_totp_secret = _security._totp_factory.generate_totp_secret()
            _datastore.put(user)

        send_security_token(
            user,
            form.chosen_method.data,
            user.us_totp_secret,
            user.us_phone_number,
            send_magic_link=True,
        )

        if _security._want_json(request):
            # Not authenticated yet - so don't send any user info.
            return base_render_json(form, include_user=False)

        return _security.render_template(
            config_value("US_SIGNIN_TEMPLATE"),
            us_signin_form=form,
            methods=config_value("US_ENABLED_METHODS"),
            chosen_method=form.chosen_method.data,
            code_sent=True,
            skip_loginmenu=True,
            **_security._run_ctx_processor("us_signin")
        )

    # Here on GET or failed validation
    if _security._want_json(request):
        payload = {"methods": config_value("US_ENABLED_METHODS")}
        return base_render_json(form, include_user=False, additional=payload)

    return _security.render_template(
        config_value("US_SIGNIN_TEMPLATE"),
        us_signin_form=form,
        methods=config_value("US_ENABLED_METHODS"),
        skip_loginmenu=True,
        **_security._run_ctx_processor("us_signin")
    )


@anonymous_user_required
@unauth_csrf(fall_through=True)
def us_signin():
    """
    Unified sign in view.
    This takes an identity (as configured in USER_IDENTITY_ATTRIBUTES)
    and a passcode (password or OTP).
    """
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
        after_this_request(_commit)
        login_user(form.user, remember=form.remember.data)

        if _security._want_json(request):
            return base_render_json(form, include_auth_token=True)

        return redirect(get_post_login_redirect())

    # Here on GET or failed POST validate
    if _security._want_json(request):
        payload = {
            "methods": config_value("US_ENABLED_METHODS"),
            "identity_attributes": config_value("USER_IDENTITY_ATTRIBUTES"),
        }
        return base_render_json(form, include_user=False, additional=payload)

    # On error - wipe code
    form.passcode.data = None
    return _security.render_template(
        config_value("US_SIGNIN_TEMPLATE"),
        us_signin_form=form,
        methods=config_value("US_ENABLED_METHODS"),
        skip_login_menu=True,
        **_security._run_ctx_processor("us_signin")
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

    if not user.us_totp_secret or not _security._totp_factory.verify_totp(
        token=request.args.get("code"),
        totp_secret=user.us_totp_secret,
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

    login_user(user)
    after_this_request(_commit)
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


@auth_required()
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

    if form.validate_on_submit():
        if not current_user.us_totp_secret or form.new_totp_secret.data:
            totp = _security._totp_factory.generate_totp_secret()
        else:
            totp = current_user.us_totp_secret
        # N.B. totp (totp_secret) is actually encrypted - so it seems safe enough
        # to send it to the user.
        state = {
            "totp_secret": totp,
            "chosen_method": form.chosen_method.data,
            "phone_number": _security._phone_util.get_canonical_form(form.phone.data),
        }
        send_security_token(
            user=current_user,
            method=form.chosen_method.data,
            totp_secret=state["totp_secret"],
            phone_number=state["phone_number"],
        )
        state_token = _security.us_setup_serializer.dumps(state)

        if _security._want_json(request):
            payload = {"state": state_token, "chosen_method": form.chosen_method.data}
            return base_render_json(form, include_user=False, additional=payload)
        return _security.render_template(
            config_value("US_SETUP_TEMPLATE"),
            methods=config_value("US_ENABLED_METHODS"),
            chosen_method=form.chosen_method.data,
            us_setup_form=form,
            us_setup_verify_form=_security.us_setup_verify_form(),
            state=state_token,
            **_security._run_ctx_processor("us_setup")
        )

    # Get here on initial new setup (GET)
    # Or failure of POST
    if _security._want_json(request):
        payload = {
            "identity_attributes": config_value("USER_IDENTITY_ATTRIBUTES"),
            "methods": config_value("US_ENABLED_METHODS"),
            "phone": current_user.us_phone_number,
        }
        return base_render_json(form, include_user=False, additional=payload)

    # Show user existing phone number
    form.phone.data = current_user.us_phone_number
    return _security.render_template(
        config_value("US_SETUP_TEMPLATE"),
        methods=config_value("US_ENABLED_METHODS"),
        us_setup_form=form,
        **_security._run_ctx_processor("us_setup")
    )


@auth_required()
def us_setup_verify(token):
    """
    Verify new setup.
    The token is the state variable which is signed and timed
    and contains all the state that once confirmed will be stored in the user record.
    """

    form_class = _security.us_setup_verify_form

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
        after_this_request(_commit)
        current_user.us_totp_secret = state["totp_secret"]
        if state["chosen_method"] == "sms":
            current_user.us_phone_number = state["phone_number"]
        _datastore.put(current_user)
        us_profile_changed.send(
            app._get_current_object(), user=current_user, method=state["chosen_method"]
        )
        if _security._want_json(request):
            return base_render_json(
                form,
                include_user=False,
                additional=dict(
                    chosen_method=state["chosen_method"],
                    phone=current_user.us_phone_number,
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
    m, c = get_message("INVALID_CODE")
    do_flash(m, c)
    return redirect(url_for_security("us_setup"))


@auth_required()
def us_qrcode(token):

    if "authenticator" not in config_value("US_ENABLED_METHODS"):
        return abort(404)
    expired, invalid, state = check_and_get_token_status(
        token, "us_setup", get_within_delta("US_SETUP_WITHIN")
    )
    if expired or invalid:
        return abort(400)

    try:
        import pyqrcode

        # By convention, the URI should have the username that the user
        # logs in with.
        username = current_user.calc_username()
        url = pyqrcode.create(
            _security._totp_factory.get_totp_uri(
                username if username else "Unknown", state["totp_secret"]
            )
        )
    except ImportError:  # pragma: no cover
        raise
    from io import BytesIO

    stream = BytesIO()
    url.svg(stream, scale=3)
    return (
        stream.getvalue(),
        200,
        {
            "Content-Type": "image/svg+xml",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


def send_security_token(user, method, totp_secret, phone_number, send_magic_link=False):
    """ Generate and send the security code.
    :param user: The user to send the code to
    :param method: The method in which the code will be sent
    :param totp_secret: the unique shared secret of the user
    :param phone_number: If 'sms' phone number to send to
    :param send_magic_link: If true a magic link that can be clicked on will be sent.
      This shouldn't be sent during a setup.
    """
    token = _security._totp_factory.generate_totp_password(totp_secret)

    if method == "email":
        login_link = None
        if send_magic_link:
            login_link = url_for_security(
                "us_verify_link", email=user.email, code=token, _external=True
            )
        _security._send_mail(
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
        app._get_current_object(), user=user, method=method, token=token
    )
