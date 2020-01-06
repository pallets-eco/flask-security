# -*- coding: utf-8 -*-
"""
    flask_security.two_factor
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security two_factor module

    :copyright: (c) 2016 by Gal Stainfeld, at Emedgene
    :copyright: (c) 2019 by J. Christopher Wagner (jwag).
"""

from flask import current_app as app, session
from werkzeug.local import LocalProxy

from .utils import config_value, SmsSenderFactory, login_user
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


def send_security_token(user, method, totp_secret):
    """Sends the security token via email/sms for the specified user.
    :param user: The user to send the code to
    :param method: The method in which the code will be sent
                ('mail' or 'sms', or 'authenticator') at the moment
    :param totp_secret: a unique shared secret of the user
    """
    token_to_be_sent = _security._totp_factory.generate_totp_password(totp_secret)
    if method == "mail":
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
        to_number = user.tf_phone_number
        sms_sender = SmsSenderFactory.createSender(config_value("SMS_SERVICE"))
        sms_sender.send_sms(from_number=from_number, to_number=to_number, msg=msg)

    elif method == "google_authenticator" or method == "authenticator":
        # password are generated automatically in the authenticator apps
        pass
    tf_security_token_sent.send(
        app._get_current_object(), user=user, method=method, token=token_to_be_sent
    )


def complete_two_factor_process(
    user, primary_method, totp_secret, is_changing, remember_login=None
):
    """clean session according to process (login or changing two-factor method)
     and perform action accordingly
    """

    # update changed primary_method
    if user.tf_primary_method != primary_method:
        user.tf_primary_method = primary_method
        _datastore.put(user)

    # update changed totp_secret
    if user.tf_totp_secret != totp_secret:
        user.tf_totp_secret = totp_secret
        _datastore.put(user)

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
    user.tf_primary_method = None
    user.tf_totp_secret = None
    _datastore.put(user)
    tf_disabled.send(app._get_current_object(), user=user)
