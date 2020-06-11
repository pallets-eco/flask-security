# -*- coding: utf-8 -*-
"""
    flask_security.two_factor
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security two_factor module

    :copyright: (c) 2016 by Gal Stainfeld, at Emedgene
    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
"""

from flask import current_app as app, redirect, request, session
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy

from .utils import (
    SmsSenderFactory,
    base_render_json,
    config_value,
    do_flash,
    login_user,
    json_error_response,
    url_for_security,
)
from .signals import (
    tf_code_confirmed,
    tf_disabled,
    tf_security_token_sent,
    tf_profile_changed,
)

# Convenient references
_security = LocalProxy(lambda: app.extensions["security"])
_datastore = LocalProxy(lambda: _security.datastore)


def tf_clean_session():
    """
    Clean out ALL stuff stored in session (e.g. on logout)
    """
    if config_value("TWO_FACTOR"):
        for k in [
            "tf_state",
            "tf_user_id",
            "tf_primary_method",
            "tf_confirmed",
            "tf_remember_login",
            "tf_totp_secret",
        ]:
            session.pop(k, None)


def tf_send_security_token(user, method, totp_secret, phone_number):
    """Sends the security token via email/sms for the specified user.

    :param user: The user to send the code to
    :param method: The method in which the code will be sent
                   ('email' or 'sms', or 'authenticator') at the moment
    :param totp_secret: a unique shared secret of the user
    :param phone_number: If 'sms' phone number to send to

    There is no return value - it is assumed that exceptions are thrown by underlying
    methods that callers can catch.

    Flask-Security code should NOT call this directly -
    call :meth:`.UserMixin.tf_send_security_token`
    """
    token_to_be_sent = _security._totp_factory.generate_totp_password(totp_secret)
    if method == "email" or method == "mail":
        _security._send_mail(
            config_value("EMAIL_SUBJECT_TWO_FACTOR"),
            user.email,
            "two_factor_instructions",
            user=user,
            token=token_to_be_sent,
            username=user.calc_username(),
        )
    elif method == "sms":
        msg = "Use this code to log in: %s" % token_to_be_sent
        from_number = config_value("SMS_SERVICE_CONFIG")["PHONE_NUMBER"]
        to_number = phone_number
        sms_sender = SmsSenderFactory.createSender(config_value("SMS_SERVICE"))
        sms_sender.send_sms(from_number=from_number, to_number=to_number, msg=msg)

    elif method == "google_authenticator" or method == "authenticator":
        # password are generated automatically in the authenticator apps
        pass
    tf_security_token_sent.send(
        app._get_current_object(),
        user=user,
        method=method,
        token=token_to_be_sent,
        phone_number=phone_number,
    )


def complete_two_factor_process(
    user, primary_method, totp_secret, is_changing, remember_login=None
):
    """clean session according to process (login or changing two-factor method)
     and perform action accordingly
    """

    _datastore.tf_set(user, primary_method, totp_secret=totp_secret)

    # if we are changing two-factor method
    if is_changing:
        completion_message = "TWO_FACTOR_CHANGE_METHOD_SUCCESSFUL"
        tf_profile_changed.send(
            app._get_current_object(), user=user, method=primary_method
        )
    # if we are logging in for the first time
    else:
        completion_message = "TWO_FACTOR_LOGIN_SUCCESSFUL"
        tf_code_confirmed.send(
            app._get_current_object(), user=user, method=primary_method
        )
        login_user(user, remember=remember_login)
    tf_clean_session()
    return completion_message


def tf_disable(user):
    """ Disable two factor for user """
    tf_clean_session()
    _datastore.tf_reset(user)
    tf_disabled.send(app._get_current_object(), user=user)


def is_tf_setup(user):
    """ Return True is user account is setup for 2FA. """
    return user.tf_totp_secret and user.tf_primary_method


def tf_login(user, remember=None, primary_authn_via=None):
    """ Helper for two-factor authentication login

    This is called only when login/password have already been validated.
    This can be from login, register, confirm, unified sign in, unified magic link.

    The result of this is either sending a 2FA token OR starting setup for new user.
    In either case we do NOT log in user, so we must store some info in session to
    track our state (including what user).
    """

    # on initial login clear any possible state out - this can happen if on same
    # machine log in  more than once since for 2FA you are not authenticated
    # until complete 2FA.
    tf_clean_session()

    session["tf_user_id"] = user.id
    if "remember":
        session["tf_remember_login"] = remember

    # Set info into form for JSON response
    json_response = {"tf_required": True}
    # if user's two-factor properties are not configured
    if user.tf_primary_method is None or user.tf_totp_secret is None:
        session["tf_state"] = "setup_from_login"
        json_response["tf_state"] = "setup_from_login"
        if not _security._want_json(request):
            return redirect(url_for_security("two_factor_setup"))

    # if user's two-factor properties are configured
    else:
        session["tf_state"] = "ready"
        json_response["tf_state"] = "ready"
        json_response["tf_primary_method"] = user.tf_primary_method

        msg = user.tf_send_security_token(
            method=user.tf_primary_method,
            totp_secret=user.tf_totp_secret,
            phone_number=getattr(user, "tf_phone_number", None),
        )
        if msg:
            # send code didn't work
            if not _security._want_json(request):
                # This is a mess - we are deep down in the login/unified sign in flow.
                do_flash(msg, "error")
                return redirect(url_for_security("login"))
            else:
                payload = json_error_response(errors=msg)
                return _security._render_json(payload, 500, None, None)

        if not _security._want_json(request):
            return redirect(url_for_security("two_factor_token_validation"))

    # JSON response - Fake up a form - doesn't really matter which.
    form = _security.login_form(MultiDict([]))
    form.user = user

    return base_render_json(form, include_user=False, additional=json_response)
