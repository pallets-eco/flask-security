"""
    flask_security.two_factor
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security two_factor module

    :copyright: (c) 2016 by Gal Stainfeld, at Emedgene
    :copyright: (c) 2019-2024 by J. Christopher Wagner (jwag).
"""

from __future__ import annotations

import typing as t

from flask import current_app, redirect, request, session

from .forms import (
    get_form_field_xlate,
    DummyForm,
    TwoFactorRescueForm,
)
from .proxies import _security, _datastore
from .tf_plugin import TfPluginBase, tf_clean_session
from .utils import (
    _,
    SmsSenderFactory,
    base_render_json,
    config_value as cv,
    do_flash,
    json_error_response,
    send_mail,
    url_for_security,
)
from .signals import (
    tf_code_confirmed,
    tf_disabled,
    tf_security_token_sent,
    tf_profile_changed,
)

if t.TYPE_CHECKING:  # pragma: no cover
    import flask
    from flask_security import Security, UserMixin
    from flask.typing import ResponseValue


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
        send_mail(
            cv("EMAIL_SUBJECT_TWO_FACTOR"),
            user.email,
            "two_factor_instructions",
            user=user,
            token=token_to_be_sent,
            username=user.calc_username(),
        )
    elif method == "sms":
        msg = f"Use this code to log in: {token_to_be_sent}"
        from_number = cv("SMS_SERVICE_CONFIG")["PHONE_NUMBER"]
        to_number = phone_number
        sms_sender = SmsSenderFactory.createSender(cv("SMS_SERVICE"))
        sms_sender.send_sms(from_number=from_number, to_number=to_number, msg=msg)

    else:
        # password are generated automatically in the authenticator apps or not needed
        token_to_be_sent = None

    tf_security_token_sent.send(
        current_app._get_current_object(),
        _async_wrapper=current_app.ensure_sync,
        user=user,
        method=method,
        token=token_to_be_sent,
        login_token=token_to_be_sent,
        phone_number=phone_number,
    )


def complete_two_factor_process(user, primary_method, totp_secret, is_changing):
    """clean session according to process (login or changing two-factor method)
    and perform action accordingly
    """

    _datastore.tf_set(user, primary_method, totp_secret=totp_secret)

    # if we are changing two-factor method
    dologin = False
    if is_changing:
        # As of 5.5.0 this is the legacy path (using session data)
        completion_message = "TWO_FACTOR_CHANGE_METHOD_SUCCESSFUL"
        tf_profile_changed.send(
            current_app._get_current_object(),
            _async_wrapper=current_app.ensure_sync,
            user=user,
            method=primary_method,
        )
    # if we are logging in for the first time
    else:
        completion_message = "TWO_FACTOR_LOGIN_SUCCESSFUL"
        tf_code_confirmed.send(
            current_app._get_current_object(),
            _async_wrapper=current_app.ensure_sync,
            user=user,
            method=primary_method,
        )
        dologin = True
    token = _security.two_factor_plugins.tf_complete(user, dologin)
    return completion_message, token


def set_rescue_options(form: TwoFactorRescueForm, user: UserMixin) -> dict[str, str]:
    # Based on config - set up options for rescue.
    # Note that this modifies the passed in Form as well as returns
    # a dict that can be returned as part of a JSON response.
    recovery_options = dict(help=url_for_security("two_factor_rescue"))

    if cv("TWO_FACTOR_RESCUE_EMAIL"):
        recovery_options["email"] = url_for_security("two_factor_rescue")
        form.help_setup.choices.append(
            ("email", get_form_field_xlate(_("Send code via email")))
        )

    if (
        _security.support_mfa
        and cv("MULTI_FACTOR_RECOVERY_CODES")
        and _datastore.mf_get_recovery_codes(user)
    ):
        recovery_options["recovery_code"] = url_for_security("mf_recovery")
        form.help_setup.choices.append(
            (
                "recovery_code",
                get_form_field_xlate(_("Use previously downloaded recovery code")),
            )
        )
    return recovery_options


def tf_disable(user):
    """Disable two factor for user"""
    tf_clean_session()
    _datastore.tf_reset(user)
    tf_disabled.send(
        current_app._get_current_object(),
        _async_wrapper=current_app.ensure_sync,
        user=user,
    )


def is_tf_setup(user):
    """Return True is user account is setup for 2FA."""
    return user.tf_totp_secret and user.tf_primary_method


class CodeTfPlugin(TfPluginBase):
    def __init__(self, app: flask.Flask):
        super().__init__(app)

    def create_blueprint(
        self, app: flask.Flask, bp: flask.Blueprint, state: Security
    ) -> None:
        pass

    def get_setup_methods(self, user: UserMixin) -> list[str]:
        if is_tf_setup(user):
            assert user.tf_primary_method is not None
            return [user.tf_primary_method]
        return []

    def tf_login(
        self, user: UserMixin, json_payload: dict[str, t.Any], next_loc: str | None
    ) -> ResponseValue:
        """Helper for two-factor authentication login

        This is called only when login/password have already been validated.
        This can be from login, register, confirm, unified sign in, unified magic link.

        If two-factor is already setup then this sends a code if the method requires it.
        If not, then user is redirected to two-factor-setup.
        In either case we do NOT log in user, so we must store some info in session to
        track our state (including what user).
        """

        # if user's two-factor properties are not configured
        if not is_tf_setup(user):
            session["tf_state"] = "setup_from_login"
            json_payload["tf_state"] = "setup_from_login"
            if not _security._want_json(request):
                return redirect(url_for_security("two_factor_setup"))

        # if user's two-factor properties are configured
        else:
            session["tf_state"] = "ready"
            json_payload["tf_state"] = "ready"
            json_payload["tf_primary_method"] = user.tf_primary_method
            json_payload["tf_method"] = user.tf_primary_method

            if user.tf_primary_method in ["mail", "email", "sms"]:
                msg = user.tf_send_security_token(
                    method=user.tf_primary_method,
                    totp_secret=user.tf_totp_secret,
                    phone_number=getattr(user, "tf_phone_number", None),
                )
                if msg:
                    # send code didn't work
                    if not _security._want_json(request):
                        # This is a mess -
                        # we are deep down in the login/unified sign in flow.
                        do_flash(msg, "error")
                        return redirect(url_for_security("login"))
                    else:
                        payload = json_error_response(errors=msg)
                        return _security._render_json(payload, 500, None, None)

            if not _security._want_json(request):
                values = dict(next=next_loc) if next_loc else dict()
                return redirect(
                    url_for_security("two_factor_token_validation", **values)
                )

        # JSON response - Fake up a form - doesn't really matter which.
        form = DummyForm(formdata=None)
        return base_render_json(form, include_user=False, additional=json_payload)
