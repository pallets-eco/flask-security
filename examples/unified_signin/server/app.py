"""
Copyright 2020-2022 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.

A simple example of server and client utilizing unified sign in and other
features of Flask-Security.

In order to be self contained, to support things like email confirmation and
unified sign in with email, we hack a Mail handler that stores the email link
and an un-protected API to fetch it!

This example is designed for a JSON and session cookie based client.

"""
import datetime
import os

from flask import Flask
from flask_babel import Babel
from flask_security import (
    Security,
    SmsSenderFactory,
    SmsSenderBaseClass,
    uia_phone_mapper,
    uia_email_mapper,
)
from flask_wtf import CSRFProtect

from models import db, user_datastore


class CaptureMail:
    # A hack Mail service that simply captures what would be sent.
    def __init__(self, app):
        app.extensions["mail"] = self
        self.sent = list()

    def send(self, msg):
        self.sent.append(msg.body)

    def pop(self):
        if len(self.sent):
            return self.sent.pop(0)
        return None


class SmsCaptureSender(SmsSenderBaseClass):
    # A hack SMS service that records SMS messages
    SmsSenderBaseClass.messages = []

    def __init__(self):
        super().__init__()
        SmsSenderBaseClass.messages = []

    def send_sms(self, from_number, to_number, msg):
        SmsSenderBaseClass.messages.append(msg)
        return

    @classmethod
    def pop(cls):
        if len(SmsSenderBaseClass.messages):
            return SmsSenderBaseClass.messages.pop(0)
        return None


def create_app():
    app = Flask(__name__)
    app.config["DEBUG"] = True
    # SECRET_KEY generated using: secrets.token_urlsafe()
    app.config["SECRET_KEY"] = "pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw"
    # PASSWORD_SALT secrets.SystemRandom().getrandbits(128)
    app.config["SECURITY_PASSWORD_SALT"] = "156043940537155509276282232127182067465"

    # We aren't interested in form-based APIs - so no need for flashing.
    app.config["SECURITY_FLASH_MESSAGES"] = False

    # Allow signing in with a phone number or email
    app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"] = [
        {"email": {"mapper": uia_email_mapper, "case_insensitive": True}},
        {"us_phone_number": {"mapper": uia_phone_mapper}},
    ]
    app.config["SECURITY_US_ENABLED_METHODS"] = ["password", "email", "sms"]

    app.config["SECURITY_TOTP_SECRETS"] = {
        "1": "TjQ9Qa31VOrfEzuPy4VHQWPCTmRzCnFzMKLxXYiZu9B"
    }

    # These need to be defined to handle redirects
    # As defined in the API documentation - they will receive the relevant context
    app.config["SECURITY_LOGIN_ERROR_VIEW"] = "/redir/login-error"
    app.config["SECURITY_POST_CONFIRM_VIEW"] = "/redir/confirmed"
    app.config["SECURITY_CONFIRM_ERROR_VIEW"] = "/redir/confirm-error"
    app.config["SECURITY_RESET_VIEW"] = "/redir/reset-password"
    app.config["SECURITY_RESET_ERROR_VIEW"] = "/redir/reset-password-error"
    app.config["SECURITY_REDIRECT_BEHAVIOR"] = "spa"

    # CSRF protection is critical for all session-based browser UIs
    # In general, most applications don't need CSRF on unauthenticated endpoints
    app.config["SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS"] = True

    # Send Cookie with csrf-token. This is the default for Axios and Angular.
    app.config["SECURITY_CSRF_COOKIE_NAME"] = "XSRF-TOKEN"
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    app.config["WTF_CSRF_TIME_LIMIT"] = None

    # have session and remember cookie be samesite (flask/flask_login)
    app.config["REMEMBER_COOKIE_SAMESITE"] = "strict"
    app.config["SESSION_COOKIE_SAMESITE"] = "strict"

    # This means the first 'fresh-required' endpoint after login will always require
    # re-verification - but after that the grace period will kick in.
    # This isn't likely something a normal app would need/want to do.
    app.config["SECURITY_FRESHNESS"] = datetime.timedelta(minutes=0)
    app.config["SECURITY_FRESHNESS_GRACE_PERIOD"] = datetime.timedelta(minutes=2)

    # As of Flask-SQLAlchemy 2.4.0 it is easy to pass in options directly to the
    # underlying engine. This option makes sure that DB connections from the pool
    # are still valid. Important for entire application since many DBaaS options
    # automatically close idle connections.
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

    # Initialize a fake SMS service that captures SMS messages
    app.config["SECURITY_SMS_SERVICE"] = "capture"
    SmsSenderFactory.senders["capture"] = SmsCaptureSender

    # Turn on all features (except passwordless since that removes normal login)
    for opt in [
        "changeable",
        "recoverable",
        "registerable",
        "trackable",
        "confirmable",
        "two_factor",
        "unified_signin",
    ]:
        app.config["SECURITY_" + opt.upper()] = True

    if os.environ.get("SETTINGS"):
        # Load settings from a file pointed to by SETTINGS
        app.config.from_envvar("SETTINGS")

    # Initialize standard Flask extensions
    CaptureMail(app)
    Babel(app)
    # Enable CSRF on all api endpoints.
    CSRFProtect(app)
    db.init_app(app)
    # Setup Flask-Security
    app.security = Security(app, user_datastore)

    # Init our API
    from api import api

    app.register_blueprint(api, url_prefix="/api")
    return app


if __name__ == "__main__":
    myapp = create_app()
    with myapp.app_context():
        db.create_all()

    myapp.run(port=5002)
