"""
    flask_security.views
    ~~~~~~~~~~~~~~~~~~~~

    Flask-Security views module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    CSRF is tricky. By default all our forms have CSRF protection built in via
    Flask-WTF. This is regardless of authentication method or whether the request
    is Form or JSON based. Form-based 'just works' since when rendering the form
    (on GET), the CSRF token is automatically populated.
    We want to handle:
        - JSON requests where CSRF token is in a header (e.g. X-CSRF-Token)
        - Option to skip CSRF when using a token to authenticate (rather than session)
          (CSRF_PROTECT_MECHANISMS)
        - Option to skip CSRF for 'login'/unauthenticated requests
          (CSRF_IGNORE_UNAUTH_ENDPOINTS)
    This is complicated by the fact that the only way to disable form CSRF is to
    pass in meta={csrf: false} at form instantiation time.

    Be aware that for CSRF to work, caller MUST pass in session cookie. So
    for pure API, and no session cookie - there is no way to support CSRF-Login
    so app must set CSRF_IGNORE_UNAUTH_ENDPOINTS (or use CSRF/session cookie for logging
    in then once they have a token, no need for cookie).

    TODO: two-factor routes such as tf_setup need work. They seem to support both
    authenticated (via session?) as well as unauthenticated access.
"""

from functools import partial
import time

from flask import (
    Blueprint,
    after_this_request,
    current_app,
    jsonify,
    request,
    session,
)
from flask_login import current_user
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy

from .changeable import change_user_password
from .confirmable import (
    confirm_email_token_status,
    confirm_user,
    send_confirmation_instructions,
)
from .decorators import anonymous_user_required, auth_required, unauth_csrf
from .passwordless import login_token_status, send_login_instructions
from .quart_compat import get_quart_status
from .unified_signin import (
    us_signin,
    us_signin_send_code,
    us_setup,
    us_setup_validate,
    us_verify,
    us_verify_link,
    us_verify_send_code,
)
from .recoverable import (
    reset_password_token_status,
    send_reset_password_instructions,
    update_password,
)
from .registerable import register_user
from .twofactor import (
    complete_two_factor_process,
    generate_tf_validity_token,
    is_tf_setup,
    tf_clean_session,
    tf_disable,
    tf_login,
    tf_set_validity_token_cookie,
    tf_verify_validility_token,
)
from .utils import (
    base_render_json,
    check_and_update_authn_fresh,
    config_value,
    do_flash,
    get_message,
    get_post_login_redirect,
    get_post_logout_redirect,
    get_post_register_redirect,
    get_post_verify_redirect,
    get_request_attr,
    get_url,
    json_error_response,
    login_user,
    logout_user,
    send_mail,
    slash_url_suffix,
    suppress_form_csrf,
    url_for_security,
    view_commit,
)

if get_quart_status():  # pragma: no cover
    from quart import make_response, redirect
else:
    from flask import make_response, redirect


# Convenient references
_security = LocalProxy(lambda: current_app.extensions["security"])
_datastore = LocalProxy(lambda: _security.datastore)


def default_render_json(payload, code, headers, user):
    """Default JSON response handler."""
    # Force Content-Type header to json.
    if headers is None:
        headers = dict()
    headers["Content-Type"] = "application/json"
    payload = dict(meta=dict(code=code), response=payload)
    return make_response(jsonify(payload), code, headers)


def _ctx(endpoint):
    return _security._run_ctx_processor(endpoint)


@unauth_csrf(fall_through=True)
def login():
    """View function for login view

    Allow already authenticated users. For GET this is useful for
    single-page-applications on refresh - session still active but need to
    access user info and csrf-token.
    For POST - redirects to POST_LOGIN_VIEW (forms) or returns 400 (json).
    """

    if current_user.is_authenticated and request.method == "POST":
        # Just redirect current_user to POST_LOGIN_VIEW.
        # While its tempting to try to logout the current user and login the
        # new requested user - that simply doesn't work with CSRF.

        # This does NOT use get_post_login_redirect() so that it doesn't look at
        # 'next' - which can cause infinite redirect loops
        # (see test_common::test_authenticated_loop)
        if _security._want_json(request):
            payload = json_error_response(
                errors=get_message("ANONYMOUS_USER_REQUIRED")[0]
            )
            return _security._render_json(payload, 400, None, None)
        else:
            return redirect(get_url(_security.post_login_view))

    form_class = _security.login_form

    if request.is_json:
        # Allow GET so we can return csrf_token for pre-login.
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(MultiDict([]), meta=suppress_form_csrf())
    else:
        form = form_class(request.form, meta=suppress_form_csrf())

    if form.validate_on_submit():
        remember_me = form.remember.data if "remember" in form else None
        if config_value("TWO_FACTOR"):
            if request.is_json and request.content_length:
                tf_validity_token = request.get_json().get("tf_validity_token", None)
            else:
                tf_validity_token = request.cookies.get("tf_validity", default=None)

            tf_validity_token_is_valid = tf_verify_validility_token(
                tf_validity_token, form.user.fs_uniquifier
            )

            if config_value("TWO_FACTOR_REQUIRED") or (is_tf_setup(form.user)):
                if config_value("TWO_FACTOR_ALWAYS_VALIDATE") or (
                    not tf_validity_token_is_valid
                ):

                    return tf_login(
                        form.user, remember=remember_me, primary_authn_via="password"
                    )

        login_user(form.user, remember=remember_me, authn_via=["password"])
        after_this_request(view_commit)

        if _security._want_json(request):
            return base_render_json(form, include_auth_token=True)
        return redirect(get_post_login_redirect())

    if _security._want_json(request):
        if current_user.is_authenticated:
            form.user = current_user
        return base_render_json(form)

    if current_user.is_authenticated:
        return redirect(get_url(_security.post_login_view))
    else:
        if form.requires_confirmation and _security.requires_confirmation_error_view:
            do_flash(*get_message("CONFIRMATION_REQUIRED"))
            return redirect(
                get_url(
                    _security.requires_confirmation_error_view,
                    qparams={"email": form.email.data},
                )
            )
        return _security.render_template(
            config_value("LOGIN_USER_TEMPLATE"), login_user_form=form, **_ctx("login")
        )


@auth_required(lambda: config_value("API_ENABLED_METHODS"))
def verify():
    """View function which handles a authentication verification request."""
    form_class = _security.verify_form

    if request.is_json:
        form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    if form.validate_on_submit():
        # form may have called verify_and_update_password()
        after_this_request(view_commit)

        # verified - so set freshness time.
        session["fs_paa"] = time.time()

        if _security._want_json(request):
            return base_render_json(form)
        do_flash(*get_message("REAUTHENTICATION_SUCCESSFUL"))
        return redirect(get_post_verify_redirect())

    if _security._want_json(request):
        assert form.user == current_user
        return base_render_json(form)

    return _security.render_template(
        config_value("VERIFY_TEMPLATE"), verify_form=form, **_ctx("verify")
    )


def logout():
    """View function which handles a logout request."""
    tf_clean_session()

    if current_user.is_authenticated:
        logout_user()

    # No body is required - so if a POST and json - return OK
    if request.method == "POST" and _security._want_json(request):
        return _security._render_json({}, 200, headers=None, user=None)

    return redirect(get_post_logout_redirect())


@anonymous_user_required
def register():
    """View function which handles a registration request."""

    # For some unknown historic reason - if you don't require confirmation
    # (via email) then you need to type in your password twice. That might
    # make sense if you can't reset your password but in modern (2020) UX models
    # don't ask twice.
    if _security.confirmable or request.is_json:
        form_class = _security.confirm_register_form
    else:
        form_class = _security.register_form

    if request.is_json:
        form_data = MultiDict(request.get_json())
    else:
        form_data = request.form

    form = form_class(form_data, meta=suppress_form_csrf())
    if form.validate_on_submit():
        did_login = False
        user = register_user(form)
        form.user = user

        # The 'auto-login' feature probably should be removed - I can't imagine
        # an application that would want random email accounts. It has been like this
        # since the beginning. Note that we still enforce 2FA - however for unified
        # signin - we adhere to historic behavior.
        if not _security.confirmable or _security.login_without_confirmation:
            if config_value("TWO_FACTOR") and config_value("TWO_FACTOR_REQUIRED"):
                return tf_login(user, primary_authn_via="register")
            after_this_request(view_commit)
            login_user(user, authn_via=["register"])
            did_login = True

        if not _security._want_json(request):
            return redirect(get_post_register_redirect())

        # Only include auth token if in fact user is permitted to login
        return base_render_json(form, include_auth_token=did_login)
    if _security._want_json(request):
        return base_render_json(form)

    return _security.render_template(
        config_value("REGISTER_USER_TEMPLATE"),
        register_user_form=form,
        **_ctx("register"),
    )


@unauth_csrf(fall_through=True)
def send_login():
    """View function that sends login instructions for passwordless login"""

    form_class = _security.passwordless_login_form

    if request.is_json:
        form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    if form.validate_on_submit():
        send_login_instructions(form.user)
        if not _security._want_json(request):
            do_flash(*get_message("LOGIN_EMAIL_SENT", email=form.user.email))

    if _security._want_json(request):
        return base_render_json(form)

    return _security.render_template(
        config_value("SEND_LOGIN_TEMPLATE"), send_login_form=form, **_ctx("send_login")
    )


@anonymous_user_required
def token_login(token):
    """View function that handles passwordless login via a token
    Like reset-password and confirm - this is usually a GET via an email
    so from the request we can't differentiate form-based apps from non.
    """

    expired, invalid, user = login_token_status(token)

    if not user or invalid:
        m, c = get_message("INVALID_LOGIN_TOKEN")
        if _security.redirect_behavior == "spa":
            return redirect(get_url(_security.login_error_view, qparams={c: m}))
        do_flash(m, c)
        return redirect(url_for_security("login"))
    if expired:
        send_login_instructions(user)
        m, c = get_message(
            "LOGIN_EXPIRED", email=user.email, within=_security.login_within
        )
        if _security.redirect_behavior == "spa":
            return redirect(
                get_url(
                    _security.login_error_view,
                    qparams=user.get_redirect_qparams({c: m}),
                )
            )
        do_flash(m, c)
        return redirect(url_for_security("login"))

    login_user(user, authn_via=["token"])
    after_this_request(view_commit)
    if _security.redirect_behavior == "spa":
        return redirect(
            get_url(_security.post_login_view, qparams=user.get_redirect_qparams())
        )

    do_flash(*get_message("PASSWORDLESS_LOGIN_SUCCESSFUL"))

    return redirect(get_post_login_redirect())


@unauth_csrf(fall_through=True)
def send_confirmation():
    """View function which sends confirmation instructions."""

    form_class = _security.send_confirmation_form

    if request.is_json:
        form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    if form.validate_on_submit():
        send_confirmation_instructions(form.user)
        if not _security._want_json(request):
            do_flash(*get_message("CONFIRMATION_REQUEST", email=form.user.email))

    if _security._want_json(request):
        return base_render_json(form)

    return _security.render_template(
        config_value("SEND_CONFIRMATION_TEMPLATE"),
        send_confirmation_form=form,
        **_ctx("send_confirmation"),
    )


def confirm_email(token):
    """View function which handles a email confirmation request."""

    expired, invalid, user = confirm_email_token_status(token)

    if not user or invalid:
        m, c = get_message("INVALID_CONFIRMATION_TOKEN")
        if _security.redirect_behavior == "spa":
            return redirect(get_url(_security.confirm_error_view, qparams={c: m}))
        do_flash(m, c)
        return redirect(
            get_url(_security.confirm_error_view)
            or url_for_security("send_confirmation")
        )

    already_confirmed = user.confirmed_at is not None

    if expired or already_confirmed:
        if already_confirmed:
            m, c = get_message("ALREADY_CONFIRMED")
        else:
            send_confirmation_instructions(user)
            m, c = get_message(
                "CONFIRMATION_EXPIRED",
                email=user.email,
                within=_security.confirm_email_within,
            )

        if _security.redirect_behavior == "spa":
            return redirect(
                get_url(
                    _security.confirm_error_view,
                    qparams=user.get_redirect_qparams({c: m}),
                )
            )

        do_flash(m, c)
        return redirect(
            get_url(_security.confirm_error_view)
            or url_for_security("send_confirmation")
        )

    confirm_user(user)
    after_this_request(view_commit)

    if user != current_user:
        logout_user()
        if config_value("AUTO_LOGIN_AFTER_CONFIRM"):
            # N.B. this is a (small) security risk if email went to wrong place.
            # and you have the LOGIN_WITH_CONFIRMATION flag since in that case
            # you can be logged in and doing stuff - but another person could
            # get the email.
            if config_value("TWO_FACTOR") and config_value("TWO_FACTOR_REQUIRED"):
                return tf_login(user, primary_authn_via="confirm")
            login_user(user, authn_via=["confirm"])

    m, c = get_message("EMAIL_CONFIRMED")
    if _security.redirect_behavior == "spa":
        return redirect(
            get_url(
                _security.post_confirm_view, qparams=user.get_redirect_qparams({c: m})
            )
        )
    do_flash(m, c)
    return redirect(
        get_url(_security.post_confirm_view)
        or get_url(
            _security.post_login_view
            if config_value("AUTO_LOGIN_AFTER_CONFIRM")
            else _security.login_url
        )
    )


@anonymous_user_required
@unauth_csrf(fall_through=True)
def forgot_password():
    """View function that handles a forgotten password request."""

    form_class = _security.forgot_password_form

    if request.is_json:
        form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    if form.validate_on_submit():
        send_reset_password_instructions(form.user)
        if not _security._want_json(request):
            do_flash(*get_message("PASSWORD_RESET_REQUEST", email=form.user.email))

    if _security._want_json(request):
        return base_render_json(form, include_user=False)

    if form.requires_confirmation and _security.requires_confirmation_error_view:
        do_flash(*get_message("CONFIRMATION_REQUIRED"))
        return redirect(
            get_url(
                _security.requires_confirmation_error_view,
                qparams={"email": form.email.data},
            )
        )

    return _security.render_template(
        config_value("FORGOT_PASSWORD_TEMPLATE"),
        forgot_password_form=form,
        **_ctx("forgot_password"),
    )


@anonymous_user_required
@unauth_csrf(fall_through=True)
def reset_password(token):
    """View function that handles a reset password request.

    This is usually called via GET as part of an email link and redirects to
    a reset-password form
    It is called via POST to actually update the password (and then redirects to
    a post reset/login view)
    If in either case the token is either invalid or expired it redirects to
    the 'forgot-password' form.

    In the case of non-form based configuration:
    For GET normal case - redirect to RESET_VIEW?token={token}&email={email}
    For GET invalid case - redirect to RESET_ERROR_VIEW?error={error}&email={email}
    For POST normal/successful case - return 200 with new authentication token
    For POST error case return 400 with form.errors
    """

    expired, invalid, user = reset_password_token_status(token)
    form_class = _security.reset_password_form
    if request.is_json:
        form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())
    form.user = user

    if request.method == "GET":
        if not user or invalid:
            m, c = get_message("INVALID_RESET_PASSWORD_TOKEN")
            if _security.redirect_behavior == "spa":
                return redirect(get_url(_security.reset_error_view, qparams={c: m}))
            do_flash(m, c)
            return redirect(url_for_security("forgot_password"))
        if expired:
            send_reset_password_instructions(user)
            m, c = get_message(
                "PASSWORD_RESET_EXPIRED",
                email=user.email,
                within=_security.reset_password_within,
            )
            if _security.redirect_behavior == "spa":
                return redirect(
                    get_url(
                        _security.reset_error_view,
                        qparams=user.get_redirect_qparams({c: m}),
                    )
                )
            do_flash(m, c)
            return redirect(url_for_security("forgot_password"))

        # All good - for SPA - redirect to the ``reset_view``
        if _security.redirect_behavior == "spa":
            return redirect(
                get_url(
                    _security.reset_view,
                    qparams=user.get_redirect_qparams({"token": token}),
                )
            )
        # for forms - render the reset password form
        return _security.render_template(
            config_value("RESET_PASSWORD_TEMPLATE"),
            reset_password_form=form,
            reset_password_token=token,
            **_ctx("reset_password"),
        )

    # This is the POST case.
    m = None
    if not user or invalid:
        invalid = True
        m, c = get_message("INVALID_RESET_PASSWORD_TOKEN")
        if not _security._want_json(request):
            do_flash(m, c)

    if expired:
        send_reset_password_instructions(user)
        m, c = get_message(
            "PASSWORD_RESET_EXPIRED",
            email=user.email,
            within=_security.reset_password_within,
        )
        if not _security._want_json(request):
            do_flash(m, c)

    if invalid or expired:
        if _security._want_json(request):
            return _security._render_json(json_error_response(m), 400, None, None)
        else:
            return redirect(url_for_security("forgot_password"))

    if form.validate_on_submit():
        after_this_request(view_commit)
        update_password(user, form.password.data)
        if config_value("TWO_FACTOR") and (
            config_value("TWO_FACTOR_REQUIRED")
            or (form.user.tf_totp_secret and form.user.tf_primary_method)
        ):
            return tf_login(user, primary_authn_via="reset")
        login_user(user, authn_via=["reset"])
        if _security._want_json(request):
            login_form = _security.login_form()
            login_form.user = user
            return base_render_json(login_form, include_auth_token=True)
        else:
            do_flash(*get_message("PASSWORD_RESET"))
            return redirect(
                get_url(_security.post_reset_view) or get_url(_security.post_login_view)
            )

    # validation failure case - for forms - we try again including the token
    # for non-forms -  we just return errors and assume caller remembers token.
    if _security._want_json(request):
        return base_render_json(form)
    return _security.render_template(
        config_value("RESET_PASSWORD_TEMPLATE"),
        reset_password_form=form,
        reset_password_token=token,
        **_ctx("reset_password"),
    )


@auth_required(lambda: config_value("API_ENABLED_METHODS"))
def change_password():
    """View function which handles a change password request."""

    form_class = _security.change_password_form

    if request.is_json:
        form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    if form.validate_on_submit():
        after_this_request(view_commit)
        change_user_password(current_user._get_current_object(), form.new_password.data)
        if _security._want_json(request):
            form.user = current_user
            return base_render_json(form, include_auth_token=True)

        do_flash(*get_message("PASSWORD_CHANGE"))
        return redirect(
            get_url(_security.post_change_view) or get_url(_security.post_login_view)
        )

    if _security._want_json(request):
        form.user = current_user
        return base_render_json(form)

    return _security.render_template(
        config_value("CHANGE_PASSWORD_TEMPLATE"),
        change_password_form=form,
        **_ctx("change_password"),
    )


@unauth_csrf(fall_through=True)
def two_factor_setup():
    """View function for two-factor setup.

    This is used both for GET to fetch forms and POST to actually set configuration
    (and send token).

    There are 3 cases for setting up:
    1) initial login and application requires 2FA
    2) changing existing 2FA information
    3) user wanting to enable or disable 2FA (assuming application doesn't require it)

    In order to CHANGE/ENABLE/DISABLE a 2FA information, user must be properly logged in
    AND have a 'fresh' authentication.

    For initial login when 2FA required of course user can't be logged in - in this
    case we need to have been sent some
    state via the session as part of login to show a) who and b) that they successfully
    authenticated.
    """
    form_class = _security.two_factor_setup_form

    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    if not current_user.is_authenticated:
        # This is the initial login case
        # We can also get here from setup if they want to change TODO: how?
        if not all(k in session for k in ["tf_user_id", "tf_state"]) or session[
            "tf_state"
        ] not in ["setup_from_login", "validating_profile"]:
            # illegal call on this endpoint
            tf_clean_session()
            return _tf_illegal_state(form, _security.login_url)

        user = _datastore.find_user(fs_uniquifier=session["tf_user_id"])
        if not user:
            tf_clean_session()
            return _tf_illegal_state(form, _security.login_url)

    else:
        # Caller is changing their TFA profile. This requires a 'fresh' authentication
        if not check_and_update_authn_fresh(
            config_value("FRESHNESS"),
            config_value("FRESHNESS_GRACE_PERIOD"),
            get_request_attr("fs_authn_via"),
        ):
            return _security._reauthn_handler(
                config_value("FRESHNESS"), config_value("FRESHNESS_GRACE_PERIOD")
            )
        user = current_user

    if form.validate_on_submit():
        # Before storing in DB and therefore requiring 2FA we need to
        # make sure it actually works.
        # Requiring 2FA is triggered by having BOTH tf_totp_secret and
        # tf_primary_method in the user record (or having the application
        # global config TWO_FACTOR_REQUIRED)
        # Until we correctly validate the 2FA - we don't set primary_method in
        # user model but use the session to store it.
        pm = form.setup.data
        if pm == "disable":
            tf_disable(user)
            after_this_request(view_commit)
            if not _security._want_json(request):
                do_flash(*get_message("TWO_FACTOR_DISABLED"))
                return redirect(get_url(_security.post_login_view))
            else:
                return base_render_json(form)

        # Regenerate the TOTP secret on every call of 2FA setup unless it is
        # within the same session and method (e.g. upon entering the phone number)
        if pm != session.get("tf_primary_method", None):
            session["tf_totp_secret"] = _security._totp_factory.generate_totp_secret()

        session["tf_primary_method"] = pm
        session["tf_state"] = "validating_profile"
        json_response = {
            "tf_state": "validating_profile",
            "tf_primary_method": pm,
        }
        new_phone = form.phone.data if len(form.phone.data) > 0 else None
        if new_phone:
            user.tf_phone_number = new_phone
            _datastore.put(user)
            after_this_request(view_commit)

        # This form is sort of bizarre - for SMS and authenticator
        # you select, then get more info, and submit again.
        # For authenticator of course, we don't actually send anything
        # and for SMS it is the second time around that we get the phone number
        if pm == "email" or (pm == "sms" and new_phone):
            msg = user.tf_send_security_token(
                method=pm,
                totp_secret=session["tf_totp_secret"],
                phone_number=getattr(user, "tf_phone_number", None),
            )
            if msg:
                # send code didn't work
                form.setup.errors = list()
                form.setup.errors.append(msg)
                if _security._want_json(request):
                    return base_render_json(
                        form, include_user=False, error_status_code=500
                    )

        qrcode_values = dict()
        if pm == "authenticator":
            authr_setup_values = _security._totp_factory.fetch_setup_values(
                session["tf_totp_secret"], user
            )
            # Add all the values used in qrcode to json response
            json_response["tf_authr_key"] = authr_setup_values["key"]
            json_response["tf_authr_username"] = authr_setup_values["username"]
            json_response["tf_authr_issuer"] = authr_setup_values["issuer"]

            qrcode_values = dict(
                authr_qrcode=authr_setup_values["image"],
                authr_key=authr_setup_values["key"],
                authr_username=authr_setup_values["username"],
                authr_issuer=authr_setup_values["issuer"],
            )
        code_form = _security.two_factor_verify_code_form()
        if not _security._want_json(request):
            return _security.render_template(
                config_value("TWO_FACTOR_SETUP_TEMPLATE"),
                two_factor_setup_form=form,
                two_factor_verify_code_form=code_form,
                choices=config_value("TWO_FACTOR_ENABLED_METHODS"),
                chosen_method=pm,
                **qrcode_values,
                **_ctx("tf_setup"),
            )
        return base_render_json(form, include_user=False, additional=json_response)

    # We get here on GET and POST with failed validation.
    # For things like phone number - we've already done one POST
    # that succeeded and now it failed - so retain the initial info
    choices = config_value("TWO_FACTOR_ENABLED_METHODS")
    if not config_value("TWO_FACTOR_REQUIRED"):
        choices.append("disable")

    if _security._want_json(request):
        # Provide information application/UI might need to render their own form/input
        json_response = {
            "tf_required": config_value("TWO_FACTOR_REQUIRED"),
            "tf_primary_method": getattr(user, "tf_primary_method", None),
            "tf_phone_number": getattr(user, "tf_phone_number", None),
            "tf_available_methods": choices,
        }
        return base_render_json(form, include_user=False, additional=json_response)

    code_form = _security.two_factor_verify_code_form()
    return _security.render_template(
        config_value("TWO_FACTOR_SETUP_TEMPLATE"),
        two_factor_setup_form=form,
        two_factor_verify_code_form=code_form,
        choices=choices,
        chosen_method=form.setup.data,
        two_factor_required=config_value("TWO_FACTOR_REQUIRED"),
        **_ctx("tf_setup"),
    )


@unauth_csrf(fall_through=True)
def two_factor_token_validation():
    """View function for two-factor token validation

    Two cases:
    1) normal login case - everything setup correctly; normal 2FA validation
       In this case - user not logged in -
       but 'tf_state' == 'ready' or 'validating_profile'
    2) validating after CHANGE/ENABLE 2FA. In this case user logged in/authenticated

    """

    form_class = _security.two_factor_verify_code_form

    if request.is_json:
        form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    changing = current_user.is_authenticated
    if not changing:
        # This is the normal login case OR initial setup
        if (
            not all(k in session for k in ["tf_user_id", "tf_state"])
            or session["tf_state"] not in ["ready", "validating_profile"]
            or (
                session["tf_state"] == "validating_profile"
                and not all(
                    k in session for k in ["tf_primary_method", "tf_totp_secret"]
                )
            )
        ):
            # illegal call on this endpoint
            tf_clean_session()
            return _tf_illegal_state(form, _security.login_url)

        user = _datastore.find_user(fs_uniquifier=session["tf_user_id"])
        form.user = user
        if not user:
            tf_clean_session()
            return _tf_illegal_state(form, _security.login_url)

        if session["tf_state"] == "ready":
            pm = user.tf_primary_method
            totp_secret = user.tf_totp_secret
        else:
            pm = session["tf_primary_method"]
            totp_secret = session["tf_totp_secret"]
    else:
        # Changing TFA profile - user is already authenticated.
        if (
            not all(k in session for k in ["tf_state", "tf_primary_method"])
            or session["tf_state"] != "validating_profile"
        ):
            tf_clean_session()
            # logout since this seems like attack-ish/logic error
            logout_user()
            return _tf_illegal_state(form, _security.login_url)
        pm = session["tf_primary_method"]
        totp_secret = session["tf_totp_secret"]
        form.user = current_user

    form.primary_method = pm
    form.tf_totp_secret = totp_secret
    if form.validate_on_submit():
        # Success - log in user and clear all session variables
        remember = session.pop("tf_remember_login", None)
        completion_message = complete_two_factor_process(
            form.user, pm, totp_secret, changing, remember
        )

        after_this_request(view_commit)

        if not _security._want_json(request):
            after_this_request(
                partial(
                    tf_set_validity_token_cookie,
                    fs_uniquifier=form.user.fs_uniquifier,
                    remember=remember,
                )
            )
            do_flash(*get_message(completion_message))

            return redirect(get_post_login_redirect())

        if (
            not config_value("TWO_FACTOR_ALWAYS_VALIDATE") and remember
        ) and _security._want_json(request):
            token = generate_tf_validity_token(form.user.fs_uniquifier)
            json_response = {"tf_validity_token": token}
            return base_render_json(form, additional=json_response)
    # GET or not successful POST
    if _security._want_json(request):
        return base_render_json(form)

    # if we were trying to validate a new method
    if changing:
        setup_form = _security.two_factor_setup_form()

        return _security.render_template(
            config_value("TWO_FACTOR_SETUP_TEMPLATE"),
            two_factor_setup_form=setup_form,
            two_factor_verify_code_form=form,
            choices=config_value("TWO_FACTOR_ENABLED_METHODS"),
            **_ctx("tf_setup"),
        )

    # if we were trying to validate an existing method
    else:
        rescue_form = _security.two_factor_rescue_form()

        return _security.render_template(
            config_value("TWO_FACTOR_VERIFY_CODE_TEMPLATE"),
            two_factor_rescue_form=rescue_form,
            two_factor_verify_code_form=form,
            problem=None,
            **_ctx("tf_token_validation"),
        )


@anonymous_user_required
@unauth_csrf(fall_through=True)
def two_factor_rescue():
    """Function that handles a situation where user can't
    enter his two-factor validation code

    User must have already provided valid username/password.
    User must have already established 2FA

    """

    form_class = _security.two_factor_rescue_form

    if request.is_json:
        form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    if (
        not all(k in session for k in ["tf_user_id", "tf_state"])
        or session["tf_state"] != "ready"
    ):
        tf_clean_session()
        return _tf_illegal_state(form, _security.login_url)

    user = _datastore.find_user(fs_uniquifier=session["tf_user_id"])
    form.user = user
    if not user:
        tf_clean_session()
        return _tf_illegal_state(form, _security.login_url)

    rproblem = ""
    if form.validate_on_submit():
        problem = form.data["help_setup"]
        rproblem = problem
        # if the problem is that user can't access his device, w
        # e send him code through mail
        if problem == "lost_device":
            msg = form.user.tf_send_security_token(
                method="email",
                totp_secret=form.user.tf_totp_secret,
                phone_number=getattr(form.user, "tf_phone_number", None),
            )
            if msg:
                rproblem = ""
                form.help_setup.errors.append(msg)
                if _security._want_json(request):
                    return base_render_json(
                        form, include_user=False, error_status_code=500
                    )
        # send app provider a mail message regarding trouble
        elif problem == "no_mail_access":
            send_mail(
                config_value("EMAIL_SUBJECT_TWO_FACTOR_RESCUE"),
                config_value("TWO_FACTOR_RESCUE_MAIL"),
                "two_factor_rescue",
                user=form.user,
            )
        else:
            return "", 404

    if _security._want_json(request):
        return base_render_json(form, include_user=False)

    code_form = _security.two_factor_verify_code_form()
    return _security.render_template(
        config_value("TWO_FACTOR_VERIFY_CODE_TEMPLATE"),
        two_factor_verify_code_form=code_form,
        two_factor_rescue_form=form,
        rescue_mail=config_value("TWO_FACTOR_RESCUE_MAIL"),
        problem=rproblem,
        **_ctx("tf_token_validation"),
    )


def _tf_illegal_state(form, redirect_to):
    m, c = get_message("TWO_FACTOR_PERMISSION_DENIED")
    if not _security._want_json(request):
        do_flash(m, c)
        return redirect(get_url(redirect_to))
    else:
        return _security._render_json(json_error_response(m), 400, None, None)


def create_blueprint(app, state, import_name, json_encoder=None):
    """Creates the security extension blueprint"""

    bp = Blueprint(
        state.blueprint_name,
        import_name,
        url_prefix=state.url_prefix,
        subdomain=state.subdomain,
        template_folder="templates",
    )
    if json_encoder:
        bp.json_encoder = json_encoder

    if state.logout_methods is not None:
        bp.route(state.logout_url, methods=state.logout_methods, endpoint="logout")(
            logout
        )

    if state.passwordless:
        bp.route(state.login_url, methods=["GET", "POST"], endpoint="login")(send_login)
        bp.route(
            state.login_url + slash_url_suffix(state.login_url, "<token>"),
            endpoint="token_login",
        )(token_login)
    elif config_value("US_SIGNIN_REPLACES_LOGIN", app=app):
        bp.route(state.login_url, methods=["GET", "POST"], endpoint="login")(us_signin)

    else:
        bp.route(state.login_url, methods=["GET", "POST"], endpoint="login")(login)

    if config_value("FRESHNESS", app=app).total_seconds() >= 0:
        bp.route(state.verify_url, methods=["GET", "POST"], endpoint="verify")(verify)

    if state.unified_signin:
        bp.route(state.us_signin_url, methods=["GET", "POST"], endpoint="us_signin")(
            us_signin
        )
        bp.route(
            state.us_signin_send_code_url,
            methods=["GET", "POST"],
            endpoint="us_signin_send_code",
        )(us_signin_send_code)
        bp.route(state.us_setup_url, methods=["GET", "POST"], endpoint="us_setup")(
            us_setup
        )
        bp.route(
            state.us_setup_url + slash_url_suffix(state.us_setup_url, "<token>"),
            methods=["GET", "POST"],
            endpoint="us_setup_validate",
        )(us_setup_validate)

        # Freshness verification
        if config_value("FRESHNESS", app=app).total_seconds() >= 0:
            bp.route(
                state.us_verify_url, methods=["GET", "POST"], endpoint="us_verify"
            )(us_verify)
            bp.route(
                state.us_verify_send_code_url,
                methods=["GET", "POST"],
                endpoint="us_verify_send_code",
            )(us_verify_send_code)

        bp.route(state.us_verify_link_url, methods=["GET"], endpoint="us_verify_link")(
            us_verify_link
        )

    if state.two_factor:
        tf_token_validation = "two_factor_token_validation"
        bp.route(
            state.two_factor_setup_url,
            methods=["GET", "POST"],
            endpoint="two_factor_setup",
        )(two_factor_setup)
        bp.route(
            state.two_factor_token_validation_url,
            methods=["GET", "POST"],
            endpoint=tf_token_validation,
        )(two_factor_token_validation)
        bp.route(
            state.two_factor_rescue_url,
            methods=["GET", "POST"],
            endpoint="two_factor_rescue",
        )(two_factor_rescue)

    if state.registerable:
        bp.route(state.register_url, methods=["GET", "POST"], endpoint="register")(
            register
        )

    if state.recoverable:
        bp.route(state.reset_url, methods=["GET", "POST"], endpoint="forgot_password")(
            forgot_password
        )
        bp.route(
            state.reset_url + slash_url_suffix(state.reset_url, "<token>"),
            methods=["GET", "POST"],
            endpoint="reset_password",
        )(reset_password)

    if state.changeable:
        bp.route(state.change_url, methods=["GET", "POST"], endpoint="change_password")(
            change_password
        )

    if state.confirmable:
        bp.route(
            state.confirm_url, methods=["GET", "POST"], endpoint="send_confirmation"
        )(send_confirmation)
        bp.route(
            state.confirm_url + slash_url_suffix(state.confirm_url, "<token>"),
            methods=["GET", "POST"],
            endpoint="confirm_email",
        )(confirm_email)

    return bp
