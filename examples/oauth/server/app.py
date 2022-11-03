"""
Copyright 2020-2022 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.

A simple example of utilizing authlib to authenticate users

In order to be self contained, to support things like email confirmation and
unified sign in with email, we hack a Mail handler that flashes the contents of emails.

This example is designed for a form-based and session cookie based client.

This example uses github as the oauth provider. Before this example will work:
1) on github register a new oauth application and grap the CLIENT_ID and CLIENT_SECRET.
   These must be passed in as env variables:
    "GITHUB_CLIENT_ID" and "GITHUB_CLIENT_SECRET".
   See: https://docs.authlib.org/en/latest/client/flask.html# for details.
2) Register yourself with this application.

Note: by default this uses an in-memory DB - so everytime you restart you lose all
registrations. To use a real disk DB:
    set SQLALCHEMY_DATABASE_URI=sqlite:////var/tmp/oauth_example.db

"""
import os

from flask import Flask, flash, redirect, render_template_string, url_for
from flask_security import (
    Security,
    auth_required,
    login_user,
    lookup_identity,
    MailUtil,
)
from flask_wtf import CSRFProtect
from authlib.integrations.flask_client import OAuth

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
        user,
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

    # Turn on all features (except passwordless since that removes normal login)
    for opt in [
        "changeable",
        "recoverable",
        "registerable",
        "trackable",
        "confirmable",
        "two_factor",
        "unified_signin",
        "webauthn",
    ]:
        app.config["SECURITY_" + opt.upper()] = True
    app.config["SECURITY_MULTI_FACTOR_RECOVERY_CODES"] = True

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

    # Initialize standard Flask extensions
    # Enable CSRF on all api endpoints.
    CSRFProtect(app)

    # setup authlib. CLIENT_ID/SECRET are from env variables.
    oauth = OAuth(app)
    oauth.register(
        name="github",
        access_token_url="https://github.com/login/oauth/access_token",
        access_token_params=None,
        authorize_url="https://github.com/login/oauth/authorize",
        authorize_params=None,
        api_base_url="https://api.github.com/",
        client_kwargs={"scope": "user:email"},
    )
    app.extensions["oauth"] = oauth

    db.init_app(app)
    # Setup Flask-Security
    Security(app, user_datastore, mail_util_cls=FlashMailUtil)

    @app.route("/")
    @auth_required()
    def home():
        return render_template_string("Hello {{ current_user.email }}")

    @app.route("/oauthsuccess")
    @auth_required()
    def authhome():
        return render_template_string("Hello {{ current_user.email }} used oauth!")

    @app.route("/oauthlogin")
    def login():
        redirect_uri = url_for("auth", _external=True)
        return oauth.github.authorize_redirect(redirect_uri)

    @app.route("/auth")
    def auth():
        token = oauth.github.authorize_access_token()
        resp = oauth.github.get("user", token=token)
        profile = resp.json()
        # Not idea since lookup_identity will check all possible identity attributes.
        user = lookup_identity(profile["email"])
        if user:
            login_user(user)
            return redirect("/oauthsuccess")
        return redirect("/login")

    return app


if __name__ == "__main__":
    myapp = create_app()
    with myapp.app_context():
        db.create_all()
    myapp.run(port=5002)
