# -*- coding: utf-8 -*-
"""
    flask_security.two_factor
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security two_factor module

    :copyright: (c) 2016 by Gal Stainfeld, at Emedgene
    :copyright: (c) 2019 by J. Christopher Wagner (jwag).
"""

from passlib.totp import TOTP
from passlib.exc import TokenError

from flask import current_app as app, session
from werkzeug.local import LocalProxy

from .utils import send_mail, config_value, SmsSenderFactory, login_user
from .signals import (
    tf_code_confirmed,
    tf_disabled,
    tf_security_token_sent,
    tf_profile_changed,
)

# Convenient references
_security = LocalProxy(lambda: app.extensions["security"])

_datastore = LocalProxy(lambda: _security.datastore)


def tf_setup(app):
    """ Initialize a totp factory.

    The TWO_FACTOR_SECRET is used to encrypt the per-user totp_secret on disk.
    """
    secrets = config_value("TWO_FACTOR_SECRET", app=app)
    # This should be a dict with at least one entry
    if not isinstance(secrets, dict) or len(secrets) < 1:
        raise ValueError(
            "TWO_FACTOR_SECRET needs to be a dict with at least one" "entry"
        )
    return TOTP.using(
        issuer=config_value("TWO_FACTOR_URI_SERVICE_NAME", app=app), secrets=secrets
    )


def tf_clean_session():
    """
    Clean out ALL stuff stored in session (e.g. on logout)
    """
    if config_value("TWO_FACTOR"):
        for k in ["tf_state", "tf_user_id", "tf_primary_method", "tf_confirmed"]:
            session.pop(k, None)


def send_security_token(user, method, totp_secret):
    """Sends the security token via email for the specified user.
    :param user: The user to send the code to
    :param method: The method in which the code will be sent
                ('mail' or 'sms') at the moment
    :param totp_secret: a unique shared secret of the user
    """
    token_to_be_sent = get_totp_password(totp_secret)
    if method == "mail":
        send_mail(
            config_value("EMAIL_SUBJECT_TWO_FACTOR"),
            user.email,
            "two_factor_instructions",
            user=user,
            token=token_to_be_sent,
        )
    elif method == "sms":
        msg = "Use this code to log in: %s" % token_to_be_sent
        from_number = config_value("TWO_FACTOR_SMS_SERVICE_CONFIG")["PHONE_NUMBER"]
        to_number = user.tf_phone_number
        sms_sender = SmsSenderFactory.createSender(
            config_value("TWO_FACTOR_SMS_SERVICE")
        )
        sms_sender.send_sms(from_number=from_number, to_number=to_number, msg=msg)

    elif method == "google_authenticator":
        # password are generated automatically in the google authenticator app
        pass
    tf_security_token_sent.send(
        app._get_current_object(), user=user, method=method, token=token_to_be_sent
    )


def get_totp_uri(username, totp_secret):
    """ Generate provisioning url for use with the qrcode
            scanner built into the app
    :param username: username of the current user
    :param totp_secret: a unique shared secret of the user
    :return:
    """
    tp = _security._totp_factory.from_source(totp_secret)
    service_name = config_value("TWO_FACTOR_URI_SERVICE_NAME")
    return tp.to_uri(username + "@" + service_name)


def verify_totp(token, totp_secret, window=0):
    """ Verifies token for specific user_totp
    :param token - token to be check against user's secret
    :param totp_secret - a unique shared secret of the user
    :param window - optional,
        How far backward and forward in time to search for a match. Measured in seconds.
    :return: A totpMatch instance or None
    """

    # TODO - in old implementation  using onetimepass window was described
    # as 'compensate for clock skew) and 'interval_length' would say how long
    # the token is good for.
    # In passlib - 'window' means how far back and forward to look and 'clock_skew'
    # is specifically for well, clock slew.
    try:
        return _security._totp_factory.verify(token, totp_secret, window=window)
    except TokenError:
        return None


def get_totp_password(totp_secret):
    """Get time-based one-time password on the basis of given secret and time
    :param totp_secret - a unique shared secret of the user
    """
    return _security._totp_factory.from_source(totp_secret).generate().token


def generate_totp():
    """ Create new user-unique totp_secret.

    We return an encrypted json string so that when sent in a cookie or
    sent to DB - it is encrypted.

    """
    return _security._totp_factory.new().to_json(encrypt=True)


def complete_two_factor_process(user, primary_method, is_changing):
    """clean session according to process (login or changing two-factor method)
     and perform action accordingly
    """

    # only update primary_method and DB if necessary
    if user.tf_primary_method != primary_method:
        user.tf_primary_method = primary_method
        _datastore.put(user)

    # if we are changing two-factor method
    if is_changing:
        # only generate new totp secret if changing method
        user.tf_totp_secret = generate_totp()
        _datastore.put(user)

        # TODO Flashing shouldn't occur here - should be at view level to can
        # make sure not to do it for json requests.
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
        login_user(user)
    tf_clean_session()
    return completion_message


def tf_disable(user):
    """ Disable two factor for user """
    tf_clean_session()
    user.tf_primary_method = None
    user.tf_totp_secret = None
    _datastore.put(user)
    tf_disabled.send(app._get_current_object(), user=user)
