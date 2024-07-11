# :copyright: (c) 2019-2024 by J. Christopher Wagner (jwag).
# :license: MIT, see LICENSE for more details.

"""
This is a simple scaffold that can be run as an app and manually test
various views using a browser.
It can be used to test translations by adding ?lang=xx. You might need to
delete the session cookie if you need to switch between languages (it is easy to
do this with your browser development tools).

Configurations can be set via environment variables.

Runs on port 5001

An initial user: test@test.com/password is created.
If you want to register a new user - you will receive a 'flash' that has the
confirm URL (with token) you need to enter into your browser address bar.

Since we don't actually send email - we have signal handlers flash the required
data and a mail sender that flashes what mail would be sent!

"""
from __future__ import annotations

from datetime import timedelta
import os
import typing as t

from flask import Flask, flash, render_template_string, request, session
from flask_wtf import CSRFProtect

from flask_security import (
    MailUtil,
    Security,
    UserDatastore,
    UserMixin,
    WebauthnUtil,
    auth_required,
    current_user,
    SQLAlchemyUserDatastore,
    FSQLALiteUserDatastore,
)
from flask_security.signals import (
    us_security_token_sent,
    tf_security_token_sent,
    reset_password_instructions_sent,
    user_not_registered,
    user_registered,
)
from flask_security.utils import (
    hash_password,
    naive_utcnow,
    uia_email_mapper,
    uia_phone_mapper,
)


def _find_bool(v):
    if str(v).lower() in ["true"]:
        return True
    elif str(v).lower() in ["false"]:
        return False
    return v


class FlashMailUtil(MailUtil):
    def send_mail(
        self,
        template: str,
        subject: str,
        recipient: str,
        sender: str | tuple,
        body: str,
        html: str | None,
        **kwargs: t.Any,
    ) -> None:
        flash(f"Email body: {body}")


SET_LANG = False


def fsqla_datastore(app):
    from flask_sqlalchemy import SQLAlchemy
    from flask_security.models import fsqla_v3 as fsqla
    from sqlalchemy_utils import database_exists, create_database

    # Create database models and hook up.
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config.setdefault("SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    db = SQLAlchemy(app)
    fsqla.FsModels.set_db_info(db)

    class Role(db.Model, fsqla.FsRoleMixin):
        pass

    class User(db.Model, fsqla.FsUserMixin):
        pass

    class WebAuthn(db.Model, fsqla.FsWebAuthnMixin):
        pass

    with app.app_context():
        if not database_exists(db.engine.url):
            create_database(db.engine.url)
        db.create_all()
    return SQLAlchemyUserDatastore(db, User, Role, WebAuthn)


def fsqla_lite_datastore(app: Flask) -> FSQLALiteUserDatastore:
    from sqlalchemy.orm import DeclarativeBase
    from flask_sqlalchemy_lite import SQLAlchemy
    from flask_security.models import sqla as sqla
    from sqlalchemy_utils import database_exists, create_database

    # Create database models and hook up.
    app.config.setdefault("SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")

    app.config |= {
        "SQLALCHEMY_ENGINES": {
            "default": {
                "url": app.config["SQLALCHEMY_DATABASE_URI"],
                "pool_pre_ping": True,
            },
        },
    }
    db = SQLAlchemy(app)

    class Model(DeclarativeBase):
        pass

    sqla.FsModels.set_db_info(base_model=Model)

    class Role(Model, sqla.FsRoleMixin):
        __tablename__ = "role"
        pass

    class User(Model, sqla.FsUserMixin):
        __tablename__ = "user"
        pass

    class WebAuthn(Model, sqla.FsWebAuthnMixin):
        __tablename__ = "web_authn"  # N.B. this is name that Flask-SQLAlchemy gives.
        pass

    with app.app_context():
        if not database_exists(db.engine.url):
            create_database(db.engine.url)
        Model.metadata.create_all(db.engine)
    return FSQLALiteUserDatastore(db, User, Role, WebAuthn)


def create_app() -> Flask:
    # Use real templates - not test templates...
    app = Flask("view_scaffold", template_folder="../")
    app.config["DEBUG"] = True
    # SECRET_KEY generated using: secrets.token_urlsafe()
    app.config["SECRET_KEY"] = "pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw"
    # PASSWORD_SALT secrets.SystemRandom().getrandbits(128)
    app.config["SECURITY_PASSWORD_SALT"] = "156043940537155509276282232127182067465"

    app.config["LOGIN_DISABLED"] = False
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["REMEMBER_COOKIE_SAMESITE"] = "strict"
    # 'strict' causes redirect after oauth to fail since session cookie not sent
    # this just happens on first 'register' with e.g. github
    # app.config["SESSION_COOKIE_SAMESITE"] = "strict"
    app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"] = [
        {"email": {"mapper": uia_email_mapper, "case_insensitive": True}},
        {"us_phone_number": {"mapper": uia_phone_mapper}},
    ]
    # app.config["SECURITY_US_ENABLED_METHODS"] = ["password"]
    # app.config["SECURITY_US_ENABLED_METHODS"] = ["authenticator", "password"]
    # app.config["SECURITY_US_SIGNIN_REPLACES_LOGIN"] = True
    # app.config["SECURITY_WAN_ALLOW_USER_HINTS"] = False

    app.config["SECURITY_TOTP_SECRETS"] = {
        "1": "TjQ9Qa31VOrfEzuPy4VHQWPCTmRzCnFzMKLxXYiZu9B"
    }
    app.config["SECURITY_FRESHNESS"] = timedelta(minutes=10)
    app.config["SECURITY_FRESHNESS_GRACE_PERIOD"] = timedelta(minutes=20)
    app.config["SECURITY_USERNAME_ENABLE"] = True
    app.config["SECURITY_USERNAME_REQUIRED"] = True
    app.config["SECURITY_PASSWORD_REQUIRED"] = False  # allow registration w/o password
    app.config["SECURITY_RETURN_GENERIC_RESPONSES"] = False
    # enable oauth - note that this assumes that app is passes XXX_CLIENT_ID and
    # XXX_CLIENT_SECRET as environment variables.
    app.config["SECURITY_OAUTH_ENABLE"] = True
    # app.config["SECURITY_URL_PREFIX"] = "/fs"

    class TestWebauthnUtil(WebauthnUtil):
        def generate_challenge(self, nbytes: int | None = None) -> str:
            # Use a constant Challenge so we can use this app to generate gold
            # responses for use in unit testing. See test_webauthn.
            # NEVER NEVER NEVER do this in production
            return "smCCiy_k2CqQydSQ_kPEjV5a2d0ApfatcpQ1aXDmQPo"

        def origin(self) -> str:
            # Return the RP origin - normally this is just the URL of the application.
            # To test with ngrok - we need the https address that the browser originally
            # sent - it is sent as the ORIGIN header - not sure if this should be
            # default or just for testing.
            return request.origin if request.origin else request.host_url.rstrip("/")

    # Turn on all features (except passwordless since that removes normal login)
    for opt in [
        "changeable",
        "change_email",
        "recoverable",
        "registerable",
        "trackable",
        "NOTpasswordless",
        "confirmable",
        "two_factor",
        "unified_signin",
        "webauthn",
        "multi_factor_recovery_codes",
    ]:
        app.config["SECURITY_" + opt.upper()] = True

    if os.environ.get("SETTINGS"):
        # Load settings from a file pointed to by SETTINGS
        app.config.from_envvar("SETTINGS")
    # Allow any SECURITY_, SQLALCHEMY, Authlib config to be set in environment.
    for ev in os.environ:
        if (
            ev.startswith("SECURITY_")
            or ev.startswith("SQLALCHEMY_")
            or "_CLIENT_" in ev
        ):
            app.config[ev] = _find_bool(os.environ.get(ev))

    CSRFProtect(app)

    # Setup Flask-Security
    # user_datastore = fsqla_datastore(app)
    user_datastore = fsqla_lite_datastore(app)

    security = Security(
        app,
        user_datastore,
        webauthn_util_cls=TestWebauthnUtil,
        mail_util_cls=FlashMailUtil,
    )

    # Setup Babel
    def get_locale():
        # For a given session - set lang based on first request.
        # Honor explicit url request first
        global SET_LANG
        if not SET_LANG:
            session.pop("lang", None)
            SET_LANG = True
        if "lang" not in session:
            locale = request.args.get("lang", None)
            if not locale:
                locale = request.accept_languages.best
            if not locale:
                locale = "en"
            if locale:
                session["lang"] = locale
        return session.get("lang", None).replace("-", "_")

    try:
        import flask_babel

        flask_babel.Babel(app, locale_selector=get_locale)
    except ImportError:
        pass

    @user_registered.connect_via(app)
    def on_user_registered(
        myapp: Flask, user: UserMixin, confirm_token: str, **extra: dict[str, t.Any]
    ) -> None:
        flash(f"To confirm {user.email} - go to /confirm/{confirm_token}")

    @user_not_registered.connect_via(app)
    def on_user_not_registered(myapp, **extra):
        if extra.get("existing_email"):
            flash(f"Tried to register existing email: {extra['user'].email}")
        elif extra.get("existing_username"):
            flash(
                f"Tried to register email: {extra['form_data'].email.data}"
                f" with username: {extra['form_data'].username.data}"
            )
        else:
            flash("Not registered response - but ??")

    @reset_password_instructions_sent.connect_via(app)
    def on_reset(myapp, user, token, **extra):
        flash(f"Go to /reset/{token}")

    @tf_security_token_sent.connect_via(app)
    def on_token_sent(myapp, user, token, method, **extra):
        flash(
            "User {} was sent two factor token {} via {}".format(
                user.calc_username(), token, method
            )
        )

    @us_security_token_sent.connect_via(app)
    def on_us_token_sent(myapp, user, token, method, **extra):
        flash(
            "User {} was sent sign in code {} via {}".format(
                user.calc_username(), token, method
            )
        )

    # Views
    @app.route("/")
    @auth_required()
    def home():
        return render_template_string(
            """
            {% include 'security/_messages.html' %}
            {{ _fsdomain('Welcome') }} {{email}} !
            {% include "security/_menu.html" %}
            """,
            email=current_user.email,
            security=security,
        )

    @app.route("/basicauth")
    @auth_required("basic")
    def basic():
        return render_template_string("Basic auth success")

    @app.route("/protected")
    @auth_required()
    def protected():
        return render_template_string("Protected endpoint")

    return app


def add_user(
    ds: UserDatastore, email: str, password: str, role_names: list[str]
) -> None:
    pw = hash_password(password)
    roles = [ds.find_or_create_role(rn) for rn in role_names]
    ds.commit()
    user = ds.create_user(
        email=email, password=pw, active=True, confirmed_at=naive_utcnow()
    )
    ds.commit()
    for role in roles:
        ds.add_role_to_user(user, role)
    ds.commit()


if __name__ == "__main__":
    myapp = create_app()
    security: Security = myapp.extensions["security"]

    with myapp.app_context():
        test_acct = "test@test.com"
        if not security.datastore.find_user(email=test_acct):
            add_user(security.datastore, test_acct, "password", ["admin"])
            print("Created User: {} with password {}".format(test_acct, "password"))

    myapp.run(port=5001)
