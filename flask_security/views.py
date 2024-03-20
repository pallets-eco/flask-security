"""
    flask_security.views
    ~~~~~~~~~~~~~~~~~~~~

    Flask-Security views module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2024 by J. Christopher Wagner (jwag).
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

"""

from functools import partial
import time
import typing as t

from flask import (
    Blueprint,
    after_this_request,
    jsonify,
    request,
    session,
)
from flask_login import current_user

from .changeable import change_user_password
from .confirmable import (
    confirm_email_token_status,
    confirm_user,
    send_confirmation_instructions,
)
from .decorators import anonymous_user_required, auth_required, unauth_csrf
from .forms import (
    _setup_methods_xlate,
    ChangePasswordForm,
    DummyForm,
    ForgotPasswordForm,
    LoginForm,
    build_form_from_request,
    build_form,
    form_errors_munge,
    ResetPasswordForm,
    SendConfirmationForm,
    TwoFactorVerifyCodeForm,
    TwoFactorSetupForm,
    TwoFactorRescueForm,
)
from .passwordless import login_token_status, send_login_instructions
from .proxies import _security, _datastore
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
from .registerable import register_user, register_existing
from .recovery_codes import mf_recovery, mf_recovery_codes
from .tf_plugin import (
    tf_check_state,
    tf_illegal_state,
    tf_set_validity_token_cookie,
)
from .twofactor import (
    complete_two_factor_process,
    set_rescue_options,
    tf_clean_session,
    tf_disable,
)
from .utils import (
    base_render_json,
    check_and_update_authn_fresh,
    config_value as cv,
    do_flash,
    get_identity_attributes,
    get_message,
    get_post_login_redirect,
    get_post_logout_redirect,
    get_post_register_redirect,
    get_post_verify_redirect,
    get_request_attr,
    get_url,
    hash_password,
    is_user_authenticated,
    json_error_response,
    localize_callback,
    login_user,
    logout_user,
    propagate_next,
    send_mail,
    slash_url_suffix,
    url_for_security,
    view_commit,
)
from .webauthn import (
    has_webauthn,
    webauthn_delete,
    webauthn_register,
    webauthn_register_response,
    webauthn_signin,
    webauthn_signin_response,
    webauthn_verify,
    webauthn_verify_response,
)

if get_quart_status():  # pragma: no cover
    from quart import make_response, redirect
else:
    from flask import make_response, redirect

if t.TYPE_CHECKING:  # pragma: no cover
    from flask.typing import ResponseValue


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


@unauth_csrf()
def login() -> "ResponseValue":
    """View function for login view

    Allow already authenticated users. For GET this is useful for
    single-page-applications on refresh - session still active but need to
    access user info and csrf-token.
    For POST - redirects to POST_LOGIN_VIEW (forms) or returns 400 (json).
    """
    form = t.cast(LoginForm, build_form_from_request("login_form"))

    if is_user_authenticated(current_user):
        # Just redirect current_user to POST_LOGIN_VIEW.
        # While its tempting to try to logout the current user and login the
        # new requested user - that simply doesn't work with CSRF.

        # This does NOT use get_post_login_redirect() so that it doesn't look at
        # 'next' - which can cause infinite redirect loops
        # (see test_common::test_authenticated_loop)
        if _security._want_json(request):
            if request.method == "POST":
                payload = json_error_response(
                    errors=get_message("ANONYMOUS_USER_REQUIRED")[0]
                )
                return _security._render_json(payload, 400, None, None)
            else:
                form.user = current_user
                return base_render_json(form)
        else:
            return redirect(get_url(cv("POST_LOGIN_VIEW")))

    # Clean out any potential old session info - in case of previous
    # aborted 2FA attempt.
    tf_clean_session()

    if form.validate_on_submit():
        assert form.user is not None
        remember_me = form.remember.data if "remember" in form else None
        response = _security.two_factor_plugins.tf_enter(
            form.user,
            remember_me,
            "password",
            next_loc=propagate_next(request.url, form),
        )
        if response:
            return response
        # two factor not required - login user
        after_this_request(view_commit)
        login_user(form.user, remember=remember_me, authn_via=["password"])

        if _security._want_json(request):
            return base_render_json(form, include_auth_token=True)
        return redirect(get_post_login_redirect())

    if request.method == "POST" and cv("RETURN_GENERIC_RESPONSES"):
        # Validation failed - make sure PII error messages are generic
        fields_to_squash = dict(
            email=dict(replace_msg="GENERIC_AUTHN_FAILED"),
            password=dict(replace_msg="GENERIC_AUTHN_FAILED"),
        )
        if hasattr(form, "username"):
            fields_to_squash["username"] = dict(replace_msg="GENERIC_AUTHN_FAILED")
        form_errors_munge(form, fields_to_squash)

    if _security._want_json(request):
        payload = {
            "identity_attributes": get_identity_attributes(),
        }
        return base_render_json(form, additional=payload)

    if (
        form.requires_confirmation
        and cv("REQUIRES_CONFIRMATION_ERROR_VIEW")
        and not cv("RETURN_GENERIC_RESPONSES")
    ):
        assert form.user_authenticated
        do_flash(*get_message("CONFIRMATION_REQUIRED"))
        return redirect(
            get_url(
                cv("REQUIRES_CONFIRMATION_ERROR_VIEW"),
                qparams={"email": form.email.data},
            )
        )
    return _security.render_template(
        cv("LOGIN_USER_TEMPLATE"),
        login_user_form=form,
        identity_attributes=get_identity_attributes(),
        **_ctx("login"),
    )


@auth_required(lambda: cv("API_ENABLED_METHODS"))
def verify():
    """View function which handles a reauthentication request."""
    form = build_form_from_request("verify_form", user=current_user)

    if form.validate_on_submit():
        # form may have called verify_and_update_password()
        after_this_request(view_commit)

        # verified - so set freshness time.
        session["fs_paa"] = time.time()

        if _security._want_json(request):
            return base_render_json(form, include_auth_token=True)
        do_flash(*get_message("REAUTHENTICATION_SUCCESSFUL"))
        return redirect(get_post_verify_redirect())

    webauthn_available = has_webauthn(current_user, cv("WAN_ALLOW_AS_VERIFY"))
    if _security._want_json(request):
        payload = {
            "has_webauthn_verify_credential": webauthn_available,
        }
        return base_render_json(form, additional=payload)

    return _security.render_template(
        cv("VERIFY_TEMPLATE"),
        verify_form=form,
        has_webauthn_verify_credential=webauthn_available,
        wan_verify_form=build_form("wan_verify_form"),
        **_ctx("verify"),
    )


def logout():
    """View function which handles a logout request."""
    tf_clean_session()

    if is_user_authenticated(current_user):
        logout_user()

    # No body is required - so if a POST and json - return OK
    if request.method == "POST" and _security._want_json(request):
        return _security._render_json({}, 200, None, None)

    return redirect(get_post_logout_redirect())


@anonymous_user_required
@unauth_csrf()
def register() -> "ResponseValue":
    """View function which handles a registration request."""

    # For some unknown historic reason - if you don't require confirmation
    # (via email) then you need to type in your password twice. That might
    # make sense if you can't reset your password but in modern (2020) UX models
    # don't ask twice.
    if _security.confirmable or request.is_json:
        form_name = "confirm_register_form"
    else:
        form_name = "register_form"
    form = build_form_from_request(form_name)

    if form.validate_on_submit():
        after_this_request(view_commit)
        did_login = False
        user = register_user(form)
        form.user = user

        # The 'auto-login' feature probably should be removed - I can't imagine
        # an application that would want random email accounts. It has been like this
        # since the beginning. Note that we still enforce 2FA - however for unified
        # signin - we adhere to historic behavior.
        if not _security.confirmable or cv("LOGIN_WITHOUT_CONFIRMATION"):
            response = _security.two_factor_plugins.tf_enter(
                form.user, False, "register", next_loc=propagate_next(request.url, form)
            )
            if response:
                return response
            # two factor not required - login user.
            login_user(user, authn_via=["register"])
            did_login = True

        if not _security._want_json(request):
            return redirect(get_post_register_redirect())

        # Only include auth token if in fact user is permitted to login
        return base_render_json(form, include_auth_token=did_login)

    # Here on GET or failed validate
    if request.method == "POST" and cv("RETURN_GENERIC_RESPONSES"):
        gr = register_existing(form)
        if gr:
            if _security._want_json(request):
                return base_render_json(form)

            return redirect(get_post_register_redirect())

    if _security._want_json(request):
        return base_render_json(form)

    return _security.render_template(
        cv("REGISTER_USER_TEMPLATE"),
        register_user_form=form,
        **_ctx("register"),
    )


@unauth_csrf()
def send_login():
    """View function that sends login instructions for passwordless login"""
    form = build_form_from_request("passwordless_login_form")

    if form.validate_on_submit():
        send_login_instructions(form.user)
        if not _security._want_json(request):
            do_flash(*get_message("LOGIN_EMAIL_SENT", email=form.user.email))

    if _security._want_json(request):
        return base_render_json(form)

    return _security.render_template(
        cv("SEND_LOGIN_TEMPLATE"), send_login_form=form, **_ctx("send_login")
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
        if cv("REDIRECT_BEHAVIOR") == "spa":
            return redirect(get_url(cv("LOGIN_ERROR_VIEW"), qparams={c: m}))
        do_flash(m, c)
        return redirect(url_for_security("login"))
    if expired:
        send_login_instructions(user)
        m, c = get_message("LOGIN_EXPIRED", email=user.email, within=cv("LOGIN_WITHIN"))
        if cv("REDIRECT_BEHAVIOR") == "spa":
            return redirect(
                get_url(
                    cv("LOGIN_ERROR_VIEW"),
                    qparams=user.get_redirect_qparams({c: m}),
                )
            )
        do_flash(m, c)
        return redirect(url_for_security("login"))

    login_user(user, authn_via=["token"])
    after_this_request(view_commit)
    if cv("REDIRECT_BEHAVIOR") == "spa":
        return redirect(
            get_url(cv("POST_LOGIN_VIEW"), qparams=user.get_redirect_qparams())
        )

    do_flash(*get_message("PASSWORDLESS_LOGIN_SUCCESSFUL"))

    return redirect(get_post_login_redirect())


@unauth_csrf()
def send_confirmation():
    """View function which sends confirmation instructions (/confirm)."""
    form = t.cast(
        SendConfirmationForm, build_form_from_request("send_confirmation_form")
    )

    if form.validate_on_submit():
        send_confirmation_instructions(form.user)
        if not _security._want_json(request):
            do_flash(*get_message("CONFIRMATION_REQUEST", email=form.email.data))

    elif request.method == "POST" and cv("RETURN_GENERIC_RESPONSES"):
        # Here on GET or failed validate
        rinfo = dict(email=dict())
        form_errors_munge(form, rinfo)  # by suppressing errors JSON should return 200
        # Check for other errors - for default form - there aren't additional fields
        # but applications might add some (e.g. recaptcha)
        if not form.errors:
            # Make look exactly like successful (e.g. real user) request
            if not _security._want_json(request):
                do_flash(*get_message("CONFIRMATION_REQUEST", email=form.email.data))

    if _security._want_json(request):
        # Never include user info since this is an anonymous endpoint.
        return base_render_json(form, include_user=False)

    return _security.render_template(
        cv("SEND_CONFIRMATION_TEMPLATE"),
        send_confirmation_form=form,
        **_ctx("send_confirmation"),
    )


def confirm_email(token):
    """
    View function which handles an email confirmation request.
    This is always a GET from an email - so for 'spa' must always redirect.
    """

    expired, invalid, user = confirm_email_token_status(token)

    if not user or invalid or expired:
        if expired:
            m, c = get_message(
                "CONFIRMATION_EXPIRED",
                within=cv("CONFIRM_EMAIL_WITHIN"),
            )
        else:
            m, c = get_message("INVALID_CONFIRMATION_TOKEN")
        if cv("REDIRECT_BEHAVIOR") == "spa":
            return redirect(get_url(cv("CONFIRM_ERROR_VIEW"), qparams={c: m}))
        do_flash(m, c)
        return redirect(
            get_url(cv("CONFIRM_ERROR_VIEW")) or url_for_security("send_confirmation")
        )

    already_confirmed = user.confirmed_at is not None
    if already_confirmed:
        m, c = get_message("ALREADY_CONFIRMED")

        if cv("REDIRECT_BEHAVIOR") == "spa":
            # No reason to expose identity info to anyone who has the link
            return redirect(
                get_url(
                    cv("CONFIRM_ERROR_VIEW"),
                    qparams={c: m},
                )
            )

        do_flash(m, c)
        return redirect(
            get_url(cv("CONFIRM_ERROR_VIEW")) or url_for_security("send_confirmation")
        )

    confirm_user(user)
    after_this_request(view_commit)
    m, c = get_message("EMAIL_CONFIRMED")

    # ? The only case where user is logged in already would be if
    # LOGIN_WITHOUT_CONFIRMATION
    if user != current_user:
        logout_user()
        if cv("AUTO_LOGIN_AFTER_CONFIRM"):
            # N.B. this is a (small) security risk if email went to wrong place.
            # and you have the LOGIN_WITHOUT_CONFIRMATION flag since in that case
            # you can be logged in and doing stuff - but another person could
            # get the email.
            # Note also this goes against OWASP recommendations.
            response = _security.two_factor_plugins.tf_enter(
                user, False, "confirm", next_loc=propagate_next(request.url, None)
            )
            if response:
                do_flash(m, c)
                return response
            login_user(user, authn_via=["confirm"])

    if cv("REDIRECT_BEHAVIOR") == "spa":
        return redirect(
            get_url(
                cv("POST_CONFIRM_VIEW"),
                qparams=user.get_redirect_qparams({c: m}),
            )
        )
    do_flash(m, c)
    return redirect(
        get_url(cv("POST_CONFIRM_VIEW"))
        or get_url(
            cv("POST_LOGIN_VIEW") if cv("AUTO_LOGIN_AFTER_CONFIRM") else ".login"
        )
    )


@anonymous_user_required
@unauth_csrf()
def forgot_password():
    """View function that handles a forgotten password request (/reset)."""
    form = t.cast(ForgotPasswordForm, build_form_from_request("forgot_password_form"))

    if form.validate_on_submit():
        send_reset_password_instructions(form.user)
        if not _security._want_json(request):
            do_flash(*get_message("PASSWORD_RESET_REQUEST", email=form.email.data))

    elif request.method == "POST" and cv("RETURN_GENERIC_RESPONSES"):
        # Here on failed validate (POST) and want generic responses
        rinfo = dict(email=dict())
        form_errors_munge(form, rinfo)  # by suppressing errors JSON should return 200
        # Check for other errors - for default form - there aren't additional fields
        # but applications might add some (e.g. recaptcha)
        if not form.errors:
            # No OTHER errors on form.
            # Make look exactly like successful (e.g. real user) request
            hash_password("not-a-password")  # reduce timing between successful and not.
            if not _security._want_json(request):
                do_flash(*get_message("PASSWORD_RESET_REQUEST", email=form.email.data))

    if _security._want_json(request):
        # Never include user info since this is an anonymous endpoint.
        return base_render_json(form, include_user=False)

    if (
        form.requires_confirmation
        and cv("REQUIRES_CONFIRMATION_ERROR_VIEW")
        and not cv("RETURN_GENERIC_RESPONSES")
    ):
        do_flash(*get_message("CONFIRMATION_REQUIRED"))
        return redirect(
            get_url(
                cv("REQUIRES_CONFIRMATION_ERROR_VIEW"),
                qparams={"email": form.email.data},
            )
        )

    return _security.render_template(
        cv("FORGOT_PASSWORD_TEMPLATE"),
        forgot_password_form=form,
        **_ctx("forgot_password"),
    )


@anonymous_user_required
@unauth_csrf()
def reset_password(token):
    """View function that handles a reset password request (/reset/<token>).

    This is usually called via GET as part of an email link and redirects to
    a reset-password form
    It is called via POST to actually update the password (and then redirects to
    a post reset/login view)
    If in either case the token is either invalid or expired it redirects to
    the 'forgot-password' form.

    In the case of non-form based configuration:
    For GET normal case - redirect to RESET_VIEW?token={token}
    For GET invalid case - redirect to RESET_ERROR_VIEW?error={error}
    For POST normal/successful case - return 200 with new authentication token
    For POST error case return 400
    """

    expired, invalid, user = reset_password_token_status(token)
    form = t.cast(ResetPasswordForm, build_form_from_request("reset_password_form"))
    form.user = user

    if request.method == "GET":
        if not user or invalid or expired:
            if expired:
                m, c = get_message(
                    "PASSWORD_RESET_EXPIRED",
                    within=cv("RESET_PASSWORD_WITHIN"),
                )
            else:
                m, c = get_message("INVALID_RESET_PASSWORD_TOKEN")
            if cv("REDIRECT_BEHAVIOR") == "spa":
                return redirect(get_url(cv("RESET_ERROR_VIEW"), qparams={c: m}))
            do_flash(m, c)
            return redirect(url_for_security("forgot_password"))

        # All good - for SPA - redirect to the ``reset_view``
        # Still - don't include PII such as identity and email if someone
        # intercepts link they still won't necessarily know the login identity
        # (even though they can change the password!).
        if cv("REDIRECT_BEHAVIOR") == "spa":
            return redirect(
                get_url(
                    cv("RESET_VIEW"),
                    qparams={"token": token},
                )
            )
        # for forms - render the reset password form
        return _security.render_template(
            cv("RESET_PASSWORD_TEMPLATE"),
            reset_password_form=form,
            reset_password_token=token,
            **_ctx("reset_password"),
        )

    # This is the POST case.
    if not user or invalid or expired:
        if expired:
            m, c = get_message(
                "PASSWORD_RESET_EXPIRED", within=cv("RESET_PASSWORD_WITHIN")
            )
        else:
            m, c = get_message("INVALID_RESET_PASSWORD_TOKEN")

        if _security._want_json(request):
            form.form_errors.append(m)
            return base_render_json(form, include_user=False)
        else:
            do_flash(m, c)
            return redirect(url_for_security("forgot_password"))

    if form.validate_on_submit():
        after_this_request(view_commit)
        update_password(user, form.password.data)
        if cv("AUTO_LOGIN_AFTER_RESET"):
            # backwards compat - really shouldn't do this according to OWASP
            response = _security.two_factor_plugins.tf_enter(
                form.user, False, "reset", next_loc=propagate_next(request.url, None)
            )
            if response:
                return response
            # two factor not required - just login
            login_user(user, authn_via=["reset"])
            if _security._want_json(request):
                dummy_form = DummyForm(formdata=None)
                dummy_form.user = user
                return base_render_json(dummy_form, include_auth_token=True)
            else:
                do_flash(*get_message("PASSWORD_RESET"))
                return redirect(
                    get_url(cv("POST_RESET_VIEW")) or get_url(cv("POST_LOGIN_VIEW"))
                )
        else:
            if _security._want_json(request):
                return _security._render_json({}, 200, None, None)
            else:
                do_flash(*get_message("PASSWORD_RESET_NO_LOGIN"))
                return redirect(get_url(cv("POST_RESET_VIEW")) or get_url(".login"))

    # validation failure case - for forms - we try again including the token
    # for non-forms -  we just return errors and assume caller remembers token.
    if _security._want_json(request):
        return base_render_json(form)
    return _security.render_template(
        cv("RESET_PASSWORD_TEMPLATE"),
        reset_password_form=form,
        reset_password_token=token,
        **_ctx("reset_password"),
    )


@auth_required(lambda: cv("API_ENABLED_METHODS"))
def change_password():
    """View function which handles a change password request."""
    form = t.cast(ChangePasswordForm, build_form_from_request("change_password_form"))

    if not current_user.password:
        # This is case where user registered w/o a password - since we can't
        # confirm with existing password - make sure fresh using whatever authentication
        # method they have set up.
        if not check_and_update_authn_fresh(
            cv("FRESHNESS"),
            cv("FRESHNESS_GRACE_PERIOD"),
            get_request_attr("fs_authn_via"),
        ):
            return _security._reauthn_handler(
                cv("FRESHNESS"), cv("FRESHNESS_GRACE_PERIOD")
            )

    if form.validate_on_submit():
        after_this_request(view_commit)
        change_user_password(current_user._get_current_object(), form.new_password.data)
        if _security._want_json(request):
            form.user = current_user
            return base_render_json(form, include_auth_token=True)

        do_flash(*get_message("PASSWORD_CHANGE"))
        return redirect(
            get_url(cv("POST_CHANGE_VIEW")) or get_url(cv("POST_LOGIN_VIEW"))
        )

    active_password = True if current_user.password else False
    if _security._want_json(request):
        form.user = current_user
        payload = dict(active_password=active_password)
        return base_render_json(form, additional=payload)

    return _security.render_template(
        cv("CHANGE_PASSWORD_TEMPLATE"),
        change_password_form=form,
        active_password=active_password,
        **_ctx("change_password"),
    )


@unauth_csrf()
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
    form = t.cast(TwoFactorSetupForm, build_form_from_request("two_factor_setup_form"))

    if not is_user_authenticated(current_user):
        # This is the initial login case
        # We can also get here from setup if they want to change TODO: how?
        if not all(k in session for k in ["tf_user_id", "tf_state"]) or session[
            "tf_state"
        ] not in ["setup_from_login", "validating_profile"]:
            # illegal call on this endpoint
            tf_clean_session()
            return tf_illegal_state(form, cv("TWO_FACTOR_ERROR_VIEW"))

        user = _datastore.find_user(fs_uniquifier=session["tf_user_id"])
        if not user:
            tf_clean_session()
            return tf_illegal_state(form, cv("TWO_FACTOR_ERROR_VIEW"))

    else:
        # Caller is changing their TFA profile. This requires a 'fresh' authentication
        # N.B unauth_csrf has done the CSRF check already.
        if not check_and_update_authn_fresh(
            cv("FRESHNESS"),
            cv("FRESHNESS_GRACE_PERIOD"),
            get_request_attr("fs_authn_via"),
        ):
            return _security._reauthn_handler(
                cv("FRESHNESS"), cv("FRESHNESS_GRACE_PERIOD")
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
                return redirect(get_url(cv("TWO_FACTOR_POST_SETUP_VIEW")))
            else:
                return base_render_json(form)

        # Regenerate the TOTP secret on every call of 2FA setup
        totp = _security._totp_factory.generate_totp_secret()
        phone = form.phone.data if pm == "sms" else None
        session["tf_totp_secret"] = totp
        session["tf_primary_method"] = pm
        session["tf_state"] = "validating_profile"
        json_response = {
            "tf_state": "validating_profile",
            "tf_primary_method": pm,  # old
            "tf_method": pm,
        }
        if phone:
            #  TODO dont save here - wait until complete
            user.tf_phone_number = phone
            _datastore.put(user)
            after_this_request(view_commit)

        if (
            pm == "email" or pm == "sms"
        ):  # TODO not sure this is needed - send checks this
            msg = user.tf_send_security_token(
                method=pm,
                totp_secret=totp,
                phone_number=phone,
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
            authr_setup_values = _security._totp_factory.fetch_setup_values(totp, user)
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
        if _security._want_json(request):
            return base_render_json(form, include_user=False, additional=json_response)
        code_form = build_form("two_factor_verify_code_form")
        return _security.render_template(
            cv("TWO_FACTOR_SETUP_TEMPLATE"),
            two_factor_setup_form=form,
            two_factor_verify_code_form=code_form,
            choices=cv("TWO_FACTOR_ENABLED_METHODS"),
            chosen_method=pm,  # do not translate
            primary_method=localize_callback(
                _setup_methods_xlate[getattr(user, "tf_primary_method", None)]
            ),
            **qrcode_values,
            **_ctx("tf_setup"),
        )

    # We get here on GET and POST with failed validation.
    # For things like phone number - we've already done one POST
    # that succeeded and now it failed - so retain the initial info
    choices = cv("TWO_FACTOR_ENABLED_METHODS")
    if (not cv("TWO_FACTOR_REQUIRED")) and user.tf_primary_method is not None:
        choices.insert(0, "disable")

    if _security._want_json(request):
        # Provide information application/UI might need to render their own form/input
        json_response = {
            "tf_required": cv("TWO_FACTOR_REQUIRED"),
            "tf_primary_method": getattr(user, "tf_primary_method", None),  # old
            "tf_method": getattr(user, "tf_primary_method", None),
            "tf_phone_number": getattr(user, "tf_phone_number", None),
            "tf_available_methods": choices,
        }
        return base_render_json(form, include_user=False, additional=json_response)

    code_form = build_form("two_factor_verify_code_form")
    return _security.render_template(
        cv("TWO_FACTOR_SETUP_TEMPLATE"),
        two_factor_setup_form=form,
        two_factor_verify_code_form=code_form,
        choices=choices,
        chosen_method=form.setup.data,
        primary_method=localize_callback(
            _setup_methods_xlate[getattr(user, "tf_primary_method", None)]
        ),
        two_factor_required=cv("TWO_FACTOR_REQUIRED"),
        **_ctx("tf_setup"),
    )


@unauth_csrf()
def two_factor_token_validation():
    """View function for two-factor token validation

    Two cases:
    1) normal login case - everything setup correctly; normal 2FA validation
       In this case - user not logged in -
       but 'tf_state' == 'ready' or 'validating_profile'
    2) validating after CHANGE/ENABLE 2FA. In this case user logged in/authenticated
       In this case we allow a GET to get the specific enter-code form.

    """
    form = t.cast(
        TwoFactorVerifyCodeForm, build_form_from_request("two_factor_verify_code_form")
    )

    # state info in session
    pm = session.get("tf_primary_method", None)
    totp_secret = session.get("tf_totp_secret", None)
    tf_state = session.get("tf_state", None)
    tf_user_id = session.get("tf_user_id", None)

    changing = is_user_authenticated(current_user)
    if not changing:
        # This is the normal login case OR initial setup (two factor required)
        if (
            tf_state not in ["ready", "validating_profile"]
            or (tf_state == "validating_profile" and not all([pm, totp_secret]))
            or not tf_user_id
        ):
            # illegal call on this endpoint
            tf_clean_session()
            return tf_illegal_state(form, cv("TWO_FACTOR_ERROR_VIEW"))

        user = _datastore.find_user(fs_uniquifier=tf_user_id)
        form.user = user
        if not user:
            tf_clean_session()
            return tf_illegal_state(form, cv("TWO_FACTOR_ERROR_VIEW"))

        if tf_state == "ready":
            # normal login case - use saved values
            pm = user.tf_primary_method
            totp_secret = user.tf_totp_secret
    else:
        # Changing TFA profile - user is already authenticated.
        if tf_state != "validating_profile" or not all([pm, totp_secret]):
            tf_clean_session()
            # logout since this seems like attack-ish/logic error
            logout_user()
            return tf_illegal_state(form, cv("TWO_FACTOR_ERROR_VIEW"))
        form.user = current_user

    form.primary_method = pm
    form.tf_totp_secret = totp_secret
    if form.validate_on_submit():
        # Success - finish process based on 'changing' and clear all session variables
        completion_message, token = complete_two_factor_process(
            form.user, pm, totp_secret, changing
        )

        after_this_request(view_commit)
        if token:
            after_this_request(partial(tf_set_validity_token_cookie, token=token))

        if not _security._want_json(request):
            do_flash(*get_message(completion_message))
            if changing:
                return redirect(get_url(cv("TWO_FACTOR_POST_SETUP_VIEW")))
            else:
                return redirect(get_post_login_redirect())

        else:
            return base_render_json(form, include_auth_token=True)

    # GET or not successful POST

    # if we were trying to validate a new method
    if changing:
        if _security._want_json(request):
            return base_render_json(form)
        # allow app to fetch just this form (independent of /tf_setup)
        return _security.render_template(
            cv("TWO_FACTOR_VERIFY_CODE_TEMPLATE"),
            two_factor_verify_code_form=form,
            chosen_method=localize_callback(_setup_methods_xlate[pm]),
            **_ctx("tf_token_validation"),
        )

    # if we were trying to validate an existing method
    else:
        rescue_form = build_form("two_factor_rescue_form")
        recovery_options = set_rescue_options(rescue_form, form.user)
        if _security._want_json(request):
            return base_render_json(
                form, additional=dict(recovery_options=recovery_options)
            )
        return _security.render_template(
            cv("TWO_FACTOR_VERIFY_CODE_TEMPLATE"),
            two_factor_rescue_form=rescue_form,
            two_factor_verify_code_form=form,
            chosen_method=localize_callback(_setup_methods_xlate[pm]),
            problem=None,
            **_ctx("tf_token_validation"),
        )


@anonymous_user_required
@unauth_csrf()
def two_factor_rescue():
    """Function that handles a situation where user can't
    enter his two-factor validation code

    User must have already provided valid username/password.
    User must have already established 2FA

    """
    form = t.cast(
        TwoFactorRescueForm, build_form_from_request("two_factor_rescue_form")
    )

    form.user = tf_check_state(["ready"])
    if not form.user:
        return tf_illegal_state(form, cv("TWO_FACTOR_ERROR_VIEW"))

    recovery_options = set_rescue_options(form, form.user)
    rproblem = ""
    if form.validate_on_submit():
        raction = form.help_setup.data
        rproblem = raction
        if raction == "email":
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
            # drop through to GET path
        elif raction == "recovery_code":
            return redirect(url_for_security("mf_recovery"))

        # send app provider a mail message regarding trouble
        elif raction == "help":
            send_mail(
                cv("EMAIL_SUBJECT_TWO_FACTOR_RESCUE"),
                cv("TWO_FACTOR_RESCUE_MAIL"),
                "two_factor_rescue",
                user=form.user,
            )
            # drop through to GET path
        else:
            return "", 404

    if _security._want_json(request):
        return base_render_json(
            form, include_user=False, additional=dict(recovery_options=recovery_options)
        )

    code_form = build_form("two_factor_verify_code_form")
    return _security.render_template(
        cv("TWO_FACTOR_VERIFY_CODE_TEMPLATE"),
        two_factor_verify_code_form=code_form,
        two_factor_rescue_form=form,
        chosen_method=localize_callback(
            _setup_methods_xlate[form.user.tf_primary_method]
        ),
        rescue_mail=cv("TWO_FACTOR_RESCUE_MAIL"),
        problem=rproblem,
        **_ctx("tf_token_validation"),
    )


def create_blueprint(app, state, import_name):
    """Creates the security extension blueprint"""

    bp = Blueprint(
        cv("BLUEPRINT_NAME", app=app),
        import_name,
        url_prefix=cv("URL_PREFIX", app=app),
        subdomain=cv("SUBDOMAIN", app=app),
        template_folder="templates",
        static_folder=cv("STATIC_FOLDER", app),
        static_url_path=cv("STATIC_FOLDER_URL", app),
    )

    if cv("LOGOUT_METHODS", app=app) is not None:
        bp.route(
            cv("LOGOUT_URL", app=app),
            methods=cv("LOGOUT_METHODS", app=app),
            endpoint="logout",
        )(logout)

    login_url = cv("LOGIN_URL", app=app)
    if state.passwordless:
        bp.route(login_url, methods=["GET", "POST"], endpoint="login")(send_login)
        bp.route(
            login_url + slash_url_suffix(login_url, "<token>"),
            endpoint="token_login",
        )(token_login)
    elif cv("US_SIGNIN_REPLACES_LOGIN", app=app):
        bp.route(login_url, methods=["GET", "POST"], endpoint="login")(us_signin)

    else:
        bp.route(login_url, methods=["GET", "POST"], endpoint="login")(login)

    if cv("FRESHNESS", app=app).total_seconds() >= 0:
        bp.route(cv("VERIFY_URL", app=app), methods=["GET", "POST"], endpoint="verify")(
            verify
        )

    if state.unified_signin:
        us_signin_url = cv("US_SIGNIN_URL", app=app)
        us_signin_send_code_url = cv("US_SIGNIN_SEND_CODE_URL", app=app)
        us_setup_url = cv("US_SETUP_URL", app=app)
        us_verify_url = cv("US_VERIFY_URL", app=app)
        us_verify_send_code_url = cv("US_VERIFY_SEND_CODE_URL", app=app)
        us_verify_link_url = cv("US_VERIFY_LINK_URL", app=app)
        bp.route(us_signin_url, methods=["GET", "POST"], endpoint="us_signin")(
            us_signin
        )
        bp.route(
            us_signin_send_code_url,
            methods=["POST"],
            endpoint="us_signin_send_code",
        )(us_signin_send_code)

        bp.route(us_setup_url, methods=["GET", "POST"], endpoint="us_setup")(us_setup)
        bp.route(
            us_setup_url + slash_url_suffix(us_setup_url, "<token>"),
            methods=["POST"],
            endpoint="us_setup_validate",
        )(us_setup_validate)

        # Freshness verification
        if cv("FRESHNESS", app=app).total_seconds() >= 0:
            bp.route(us_verify_url, methods=["GET", "POST"], endpoint="us_verify")(
                us_verify
            )
            bp.route(
                us_verify_send_code_url,
                methods=["POST"],
                endpoint="us_verify_send_code",
            )(us_verify_send_code)

        bp.route(us_verify_link_url, methods=["GET"], endpoint="us_verify_link")(
            us_verify_link
        )

    if state.two_factor:
        two_factor_setup_url = cv("TWO_FACTOR_SETUP_URL", app=app)
        two_factor_token_validation_url = cv("TWO_FACTOR_TOKEN_VALIDATION_URL", app=app)
        two_factor_rescue_url = cv("TWO_FACTOR_RESCUE_URL", app=app)
        bp.route(
            two_factor_setup_url,
            methods=["GET", "POST"],
            endpoint="two_factor_setup",
        )(two_factor_setup)
        bp.route(
            two_factor_token_validation_url,
            methods=["GET", "POST"],
            endpoint="two_factor_token_validation",
        )(two_factor_token_validation)
        bp.route(
            two_factor_rescue_url,
            methods=["GET", "POST"],
            endpoint="two_factor_rescue",
        )(two_factor_rescue)

    if state.registerable:
        bp.route(
            cv("REGISTER_URL", app=app), methods=["GET", "POST"], endpoint="register"
        )(register)

    if state.recoverable:
        reset_url = cv("RESET_URL", app=app)
        bp.route(reset_url, methods=["GET", "POST"], endpoint="forgot_password")(
            forgot_password
        )
        bp.route(
            reset_url + slash_url_suffix(reset_url, "<token>"),
            methods=["GET", "POST"],
            endpoint="reset_password",
        )(reset_password)

    if state.changeable:
        bp.route(
            cv("CHANGE_URL", app=app),
            methods=["GET", "POST"],
            endpoint="change_password",
        )(change_password)

    if state.confirmable:
        confirm_url = cv("CONFIRM_URL", app=app)
        bp.route(confirm_url, methods=["GET", "POST"], endpoint="send_confirmation")(
            send_confirmation
        )
        bp.route(
            confirm_url + slash_url_suffix(confirm_url, "<token>"),
            methods=["GET", "POST"],
            endpoint="confirm_email",
        )(confirm_email)

    if cv("MULTI_FACTOR_RECOVERY_CODES", app) and state.support_mfa:
        multi_factor_recovery_codes_url = cv("MULTI_FACTOR_RECOVERY_CODES_URL", app=app)
        multi_factor_recovery_url = cv("MULTI_FACTOR_RECOVERY_URL", app=app)
        bp.route(
            multi_factor_recovery_codes_url,
            methods=["GET", "POST"],
            endpoint="mf_recovery_codes",
        )(mf_recovery_codes)
        bp.route(
            multi_factor_recovery_url,
            methods=["GET", "POST"],
            endpoint="mf_recovery",
        )(mf_recovery)

    if state.webauthn:
        wan_register_url = cv("WAN_REGISTER_URL", app=app)
        wan_signin_url = cv("WAN_SIGNIN_URL", app=app)
        wan_delete_url = cv("WAN_DELETE_URL", app=app)
        wan_verify_url = cv("WAN_VERIFY_URL", app=app)
        bp.route(
            wan_register_url,
            methods=["GET", "POST"],
            endpoint="wan_register",
        )(webauthn_register)
        bp.route(
            wan_register_url + slash_url_suffix(wan_register_url, "<token>"),
            methods=["POST"],
            endpoint="wan_register_response",
        )(webauthn_register_response)

        bp.route(wan_signin_url, methods=["GET", "POST"], endpoint="wan_signin")(
            webauthn_signin
        )
        bp.route(
            wan_signin_url + slash_url_suffix(wan_signin_url, "<token>"),
            methods=["POST"],
            endpoint="wan_signin_response",
        )(webauthn_signin_response)
        bp.route(wan_delete_url, methods=["GET", "POST"], endpoint="wan_delete")(
            webauthn_delete
        )
        if cv("FRESHNESS", app=app).total_seconds() >= 0 and cv(
            "WAN_ALLOW_AS_VERIFY", app=app
        ):
            bp.route(wan_verify_url, methods=["GET", "POST"], endpoint="wan_verify")(
                webauthn_verify
            )
            bp.route(
                wan_verify_url + slash_url_suffix(wan_verify_url, "<token>"),
                methods=["POST"],
                endpoint="wan_verify_response",
            )(webauthn_verify_response)

    return bp
