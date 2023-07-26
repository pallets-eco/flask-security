"""
Copyright 2020-2023 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.

A simple example of utilizing Flask-Security's oauth glue layer.

In addition, this example uses unified signin to allow for passwordless registration.
So users can log in only via social auth OR an email link.

This example also sets up and required CSRF protection for all endpoints.

In order to be self contained, to support things like email confirmation and
unified sign in with email, we hack a Mail handler that flashes the contents of emails.

This example is designed for a browser based client.

This example uses github as the oauth provider. Before this example will work:
1) on github register a new oauth application and grap the CLIENT_ID and CLIENT_SECRET.
   These must be passed in as env variables:
    "GITHUB_CLIENT_ID" and "GITHUB_CLIENT_SECRET".
   See: https://docs.authlib.org/en/latest/client/flask.html# for details.
   (look under profile->settings->developer settings)
2) Register yourself (with your github email) with this application.

Note: by default this uses an in-memory DB - so everytime you restart you lose all
registrations. To use a real disk DB:
    set SQLALCHEMY_DATABASE_URI=sqlite:////var/tmp/oauth_example.db

"""
import os

from flask import Flask, flash, render_template_string
from flask_security import (
    Security,
    auth_required,
    MailUtil,
)
from flask_wtf import CSRFProtect

from models import db, user_datastore


def _find_bool(v):
    if str(v).lower() in ["true"]:
        return True
    elif str(v).lower() in ["false"]:
        return False
    return v


class FlashMailUtil(MailUtil):
    def send_mail(
        self,
        template,
        subject,
        recipients,
        sender,
        body,
        html,
        **kwargs,
    ):
        flash(f"Email body: {body}")


def create_app():
    app = Flask(__name__)
    app.config["DEBUG"] = True
    # SECRET_KEY generated using: secrets.token_urlsafe()
    app.config["SECRET_KEY"] = "pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw"
    # PASSWORD_SALT secrets.SystemRandom().getrandbits(128)
    app.config["SECURITY_PASSWORD_SALT"] = "156043940537155509276282232127182067465"
    app.config["SECURITY_TOTP_SECRETS"] = {
        "1": "TjQ9Qa31VOrfEzuPy4VHQWPCTmRzCnFzMKLxXYiZu9B"
    }

    # As of Flask-SQLAlchemy 2.4.0 it is easy to pass in options directly to the
    # underlying engine. This option makes sure that DB connections from the pool
    # are still valid. Important for entire application since many DBaaS options
    # automatically close idle connections.
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

    # Turn on Oauth glue (github only), passwordless registration (with email link)
    app.config["SECURITY_REGISTERABLE"] = True
    app.config["SECURITY_OAUTH_ENABLE"] = True
    app.config["SECURITY_UNIFIED_SIGNIN"] = True
    app.config["SECURITY_PASSWORD_REQUIRED"] = False
    app.config["SECURITY_US_SIGNIN_REPLACES_LOGIN"] = True
    app.config["SECURITY_US_ENABLED_METHODS"] = ["email"]
    app.config["SECURITY_OAUTH_BUILTIN_PROVIDERS"] = ["github"]

    if os.environ.get("SETTINGS"):
        # Load settings from a file pointed to by SETTINGS
        app.config.from_envvar("SETTINGS")
    # Allow any SECURITY_, SQLALCHEMY_ or _CLIENT_ID or _CLIENT_SECRET config
    # to be set in environment.
    for ev in os.environ:
        if (
            ev.startswith("SECURITY_")
            or ev.startswith("SQLALCHEMY_")
            or "_CLIENT_" in ev
        ):
            app.config[ev] = _find_bool(os.environ.get(ev))

    # Enable CSRF on all api endpoints for forms and JSON
    CSRFProtect(app)

    # Setup Flask-Security
    db.init_app(app)
    Security(app, user_datastore, mail_util_cls=FlashMailUtil)

    @app.route("/")
    @auth_required()
    def home():
        return render_template_string("Hello {{ current_user.email }}")

    return app


if __name__ == "__main__":
    myapp = create_app()
    with myapp.app_context():
        db.create_all()
    myapp.run(port=5002)
