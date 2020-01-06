# -*- coding: utf-8 -*-
"""
    flask_security.passwordlessv2
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security passwordless module

    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    Finish up/Consider:
    - 2FA? since this is now a universal login - probably yes.
    - should we support a way that /logout redirects to pl-login rather than /login?
    - openapi.yaml
    - configuration.rst
    - test context processors
    - example
    - need to change password to be nullable and verify doesn't allow normal login
    - make username unique?
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
from .signals import pl_profile_changed, pl_security_token_sent
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


def _pl_common_validate(form):
    # Common validation for passwordless forms.
    # Be aware - this has side effect on the form - it will fill in
    # the form.user

    # Validate identity - we go in order to figure out which user attribute the
    # request gave us. Note that we give up on the first 'match' even if that
    # doesn't yield a user. Why?
    for mapping in config_value("USER_IDENTITY_MAPPINGS"):
        for ua, mapper in mapping.items():
            # Make sure we don't validate on a column that application
            # hasn't specifically configured as a unique/identity column
            # In other words - might have a phone number for 2FA or passwordless
            # but don't want the user to be able to use that as primary identity
            if ua in config_value("USER_IDENTITY_ATTRIBUTES"):
                # Allow mapper to alter (coerce) to type DB requires
                idata = mapper(form.identity.data)
                if idata is not None:
                    form.user = _datastore.find_user(**{ua: idata})

    if not form.user:
        form.identity.errors.append(get_message("PL_SPECIFY_IDENTITY")[0])
        return False
    if not form.user.is_active:
        form.identity.errors.append(get_message("DISABLED_ACCOUNT")[0])
        return False
    return True


class PasswordlessV2LoginForm(Form):
    """ A unified login form
    For either identity/password or request and enter code.
    """

    user = None

    # Identity can be any of the USER_IDENTITY_ATTRIBUTES
    # And xlate please
    identity = StringField(
        get_form_field_label("identity"),
        validators=[Required()],
        render_kw={"placeholder": "email, phone, username"},
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
        super(PasswordlessV2LoginForm, self).__init__(*args, **kwargs)
        self.remember.default = config_value("DEFAULT_REMEMBER_ME")

    def validate(self):
        if not super(PasswordlessV2LoginForm, self).validate():
            return False

        # For either - require a valid identity
        if not _pl_common_validate(self):
            return False

        if self.submit.data:
            # This is login - verify passcode/password
            if not self.user.pl_totp_secret or not _security._totp_factory.verify_totp(
                token=self.passcode.data,
                totp_secret=self.user.pl_totp_secret,
                user=self.user,
                window=config_value("PL_TOKEN_VALIDITY"),
            ):
                # That didn't work - maybe it's just a password
                if not self.user.verify_and_update_password(self.passcode.data):
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
            if self.chosen_method.data not in config_value("PL_ENABLED_METHODS"):
                self.chosen_method.errors.append(
                    get_message("PL_METHOD_NOT_AVAILABLE")[0]
                )
                return False
            if self.chosen_method.data == "sms" and not self.user.pl_phone_number:
                # They need to pl-setup!
                self.chosen_method.errors.append(get_message("PL_PHONE_REQUIRED")[0])
                return False
            return True
        return False  # pragma: no cover


class PasswordlessV2SetupForm(Form):
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
        super(PasswordlessV2SetupForm, self).__init__(*args, **kwargs)

    def validate(self):
        if not super(PasswordlessV2SetupForm, self).validate():
            return False
        if self.chosen_method.data not in config_value("PL_ENABLED_METHODS"):
            self.chosen_method.errors.append(get_message("PL_METHOD_NOT_AVAILABLE")[0])
            return False

        if self.chosen_method.data == "sms":
            # XXX use phone validator
            if self.phone.data is None or len(self.phone.data) == 0:
                self.phone.errors.append(get_message("PL_PHONE_REQUIRED")[0])
                return False

        return True


class PasswordlessV2SetupVerifyForm(Form):
    """The passwordless setup validation form """

    # These 2 filled in by view
    user = None
    totp_secret = None

    code = StringField(get_form_field_label("code"), validators=[Required()])
    submit = SubmitField(get_form_field_label("submitcode"))

    def __init__(self, *args, **kwargs):
        super(PasswordlessV2SetupVerifyForm, self).__init__(*args, **kwargs)

    def validate(self):
        if not super(PasswordlessV2SetupVerifyForm, self).validate():
            return False

        if not _security._totp_factory.verify_totp(
            token=self.code.data,
            totp_secret=self.totp_secret,
            user=self.user,
            window=config_value("PL_TOKEN_VALIDITY"),
        ):
            self.code.errors.append(get_message("INVALID_CODE")[0])
            return False

        return True


@anonymous_user_required
@unauth_csrf(fall_through=True)
def pl_send_code():
    """
    Send code view.
    This takes an identity (as configured in USER_IDENTITY_ATTRIBUTES)
    and a method request to send a code.
    """
    form_class = _security.pl_login_form

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
        if not user.pl_totp_secret:
            after_this_request(_commit)
            user.pl_totp_secret = _security._totp_factory.generate_totp_secret()
            _datastore.put(user)

        send_security_token(
            user,
            form.chosen_method.data,
            user.pl_totp_secret,
            user.pl_phone_number,
            send_magic_link=True,
        )

        if _security._want_json(request):
            # Not authenticated yet - so don't send any user info.
            return base_render_json(form, include_user=False)

        return _security.render_template(
            config_value("PL_LOGIN_TEMPLATE"),
            pl_login_form=form,
            methods=config_value("PL_ENABLED_METHODS"),
            chosen_method=form.chosen_method.data,
            code_sent=True,
            skip_loginmenu=True,
            **_security._run_ctx_processor("pl_login")
        )

    # Here on GET or failed validation
    if _security._want_json(request):
        payload = {"methods": config_value("PL_ENABLED_METHODS")}
        return base_render_json(form, include_user=False, additional=payload)

    return _security.render_template(
        config_value("PL_LOGIN_TEMPLATE"),
        pl_login_form=form,
        methods=config_value("PL_ENABLED_METHODS"),
        skip_loginmenu=True,
        **_security._run_ctx_processor("pl_login")
    )


@anonymous_user_required
@unauth_csrf(fall_through=True)
def pl_login():
    """
    Passwordless/unified login view.
    This takes an identity (as configured in USER_IDENTITY_ATTRIBUTES)
    and a passcode (password or OTP).
    """
    form_class = _security.pl_login_form

    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())
    form.submit.data = True

    if form.validate_on_submit():
        login_user(form.user, remember=form.remember.data)
        after_this_request(_commit)

        if _security._want_json(request):
            return base_render_json(form, include_auth_token=True)

        return redirect(get_post_login_redirect())

    # Here on GET or failed POST validate
    if _security._want_json(request):
        payload = {
            "methods": config_value("PL_ENABLED_METHODS"),
            "identity_attributes": config_value("USER_IDENTITY_ATTRIBUTES"),
        }
        return base_render_json(form, include_user=False, additional=payload)

    # On error - wipe code
    form.passcode.data = None
    return _security.render_template(
        config_value("PL_LOGIN_TEMPLATE"),
        pl_login_form=form,
        methods=config_value("PL_ENABLED_METHODS"),
        skip_login_menu=True,
        **_security._run_ctx_processor("pl_login")
    )


@anonymous_user_required
def pl_verify_link():
    """
    Used to verify a magic email link. GET only
    """
    if not all(v in request.args for v in ["email", "code"]):
        m, c = get_message("API_ERROR")
        if _security.redirect_behavior == "spa":
            return redirect(get_url(_security.login_error_view, qparams={c: m}))
        do_flash(m, c)
        return redirect(url_for_security("pl_login"))

    user = _datastore.find_user(email=request.args.get("email"))
    if not user or not user.active:
        if not user:
            m, c = get_message("USER_DOES_NOT_EXIST")
        else:
            m, c = get_message("DISABLED_ACCOUNT")
        if _security.redirect_behavior == "spa":
            return redirect(get_url(_security.login_error_view, qparams={c: m}))
        do_flash(m, c)
        return redirect(url_for_security("pl_login"))

    if not user.pl_totp_secret or not _security._totp_factory.verify_totp(
        token=request.args.get("code"),
        totp_secret=user.pl_totp_secret,
        user=user,
        window=config_value("PL_TOKEN_VALIDITY"),
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
        return redirect(url_for_security("pl_login"))

    login_user(user)
    after_this_request(_commit)
    if _security.redirect_behavior == "spa":
        # We do NOT send the authentication token here since the only way to
        # send it would be via a query param and that isn't secure. (logging and
        # possibly HTTP Referer header).
        # This means that this can only work if sessions are active which sort of
        # makes sense - otherwise you need to use /pl-verify with a code.
        return redirect(
            get_url(_security.post_login_view, qparams=user.get_redirect_qparams())
        )

    do_flash(*get_message("PASSWORDLESS_LOGIN_SUCCESSFUL"))
    return redirect(get_post_login_redirect())


@auth_required()
def pl_setup():
    """
    Change passwordless methods.
    We want to verify the new method - so don't store anything yet in DB
    use a timed signed token to pass along state.
    GET - retrieve current info (json) or form.
    """
    form_class = _security.pl_setup_form

    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    if form.validate_on_submit():
        if not current_user.pl_totp_secret or form.new_totp_secret.data:
            totp = _security._totp_factory.generate_totp_secret()
        else:
            totp = current_user.pl_totp_secret
        state = {
            "totp_secret": totp,
            "chosen_method": form.chosen_method.data,
            "phone_number": form.phone.data,
        }
        send_security_token(
            user=current_user,
            method=form.chosen_method.data,
            totp_secret=state["totp_secret"],
            phone_number=state["phone_number"],
        )
        state_token = _security.pl_setup_serializer.dumps(state)

        if _security._want_json(request):
            payload = {"state": state_token, "chosen_method": form.chosen_method.data}
            return base_render_json(form, include_user=False, additional=payload)
        return _security.render_template(
            config_value("PL_SETUP_TEMPLATE"),
            methods=config_value("PL_ENABLED_METHODS"),
            chosen_method=form.chosen_method.data,
            pl_setup_form=form,
            pl_setup_verify_form=_security.pl_setup_verify_form(),
            state=state_token,
            **_security._run_ctx_processor("pl_setup")
        )

    # Get here on initial new setup (GET)
    # Or failure of POST
    if _security._want_json(request):
        payload = {
            "identity_attributes": config_value("USER_IDENTITY_ATTRIBUTES"),
            "methods": config_value("PL_ENABLED_METHODS"),
            "phone": current_user.pl_phone_number,
        }
        return base_render_json(form, include_user=False, additional=payload)

    # Show user existing phone number
    form.phone.data = current_user.pl_phone_number
    return _security.render_template(
        config_value("PL_SETUP_TEMPLATE"),
        methods=config_value("PL_ENABLED_METHODS"),
        pl_setup_form=form,
        **_security._run_ctx_processor("pl_setup")
    )


@auth_required()
def pl_setup_verify(token):
    """
    Verify new setup.
    The token is the state variable which is signed and timed
    and contains all the state that once confirmed will be stored in the user record.
    """

    form_class = _security.pl_setup_verify_form

    if request.is_json:
        form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    expired, invalid, state = check_and_get_token_status(
        token, "pl_setup", get_within_delta("PL_SETUP_WITHIN")
    )
    if invalid:
        m, c = get_message("API_ERROR")
    if expired:
        m, c = get_message("PL_SETUP_EXPIRED", within=config_value("PL_SETUP_WITHIN"))
    if invalid or expired:
        if _security._want_json(request):
            payload = json_error_response(errors=m)
            return _security._render_json(payload, 400, None, None)
        do_flash(m, c)
        return redirect(url_for_security("pl_setup"))

    form.totp_secret = state["totp_secret"]
    form.user = current_user

    if form.validate_on_submit():
        after_this_request(_commit)
        current_user.pl_totp_secret = state["totp_secret"]
        if state["chosen_method"] == "sms":
            current_user.pl_phone_number = state["phone_number"]
        _datastore.put(current_user)
        pl_profile_changed.send(
            app._get_current_object(), user=current_user, method=state["chosen_method"]
        )
        if _security._want_json(request):
            return base_render_json(
                form,
                include_user=False,
                additional=dict(
                    chosen_method=state["chosen_method"],
                    phone=current_user.pl_phone_number,
                ),
            )
        else:
            do_flash(*get_message("PL_SETUP_SUCCESSFUL"))
            return redirect(
                get_url(_security.pl_post_setup_view)
                or get_url(_security.post_login_view)
            )

    # Code not correct/outdated.
    if _security._want_json(request):
        return base_render_json(form, include_user=False)
    m, c = get_message("INVALID_CODE")
    do_flash(m, c)
    return redirect(url_for_security("pl_setup"))


@auth_required()
def pl_qrcode(token):

    if "authenticator" not in config_value("PL_ENABLED_METHODS"):
        return abort(404)
    expired, invalid, state = check_and_get_token_status(
        token, "pl_setup", get_within_delta("PL_SETUP_WITHIN")
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
                "pl_verify_link", email=user.email, code=token, _external=True
            )
        _security._send_mail(
            config_value("PL_EMAIL_SUBJECT"),
            user.email,
            "pl_instructions",
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

    elif method == "authenticator":
        # tokens are generated automatically with authenticator apps
        pass
    pl_security_token_sent.send(
        app._get_current_object(), user=user, method=method, token=token
    )
