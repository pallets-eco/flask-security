# :copyright: (c) 2019-2023 by J. Christopher Wagner (jwag).
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

import datetime
import os
import typing as t

from flask import Flask, flash, render_template_string, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

from flask_security import (
    MailUtil,
    Security,
    WebauthnUtil,
    auth_required,
    current_user,
    login_required,
    SQLAlchemyUserDatastore,
)
from flask_security.models import fsqla_v3 as fsqla
from flask_security.signals import (
    us_security_token_sent,
    tf_security_token_sent,
    reset_password_instructions_sent,
    user_not_registered,
    user_registered,
)
from flask_security.utils import hash_password, uia_email_mapper, uia_phone_mapper


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
        sender: t.Union[str, tuple],
        body: str,
        html: t.Optional[str],
        **kwargs: t.Any,
    ) -> None:
        flash(f"Email body: {body}")


SET_LANG = False


def create_app():
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
    app.config["SECURITY_FRESHNESS"] = datetime.timedelta(minutes=1)
    app.config["SECURITY_FRESHNESS_GRACE_PERIOD"] = datetime.timedelta(minutes=2)
    app.config["SECURITY_USERNAME_ENABLE"] = True
    app.config["SECURITY_USERNAME_REQUIRED"] = True
    app.config["SECURITY_PASSWORD_REQUIRED"] = True
    app.config["SECURITY_RETURN_GENERIC_RESPONSES"] = False
    # enable oauth - note that this assumes that app is passes XXX_CLIENT_ID and
    # XXX_CLIENT_SECRET as environment variables.
    app.config["SECURITY_OAUTH_ENABLE"] = True
    # app.config["SECURITY_URL_PREFIX"] = "/fs"

    class TestWebauthnUtil(WebauthnUtil):
        def generate_challenge(self, nbytes: t.Optional[int] = None) -> str:
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
    # Create database models and hook up.
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db = SQLAlchemy(app)
    fsqla.FsModels.set_db_info(db)

    class Role(db.Model, fsqla.FsRoleMixin):
        pass

    class User(db.Model, fsqla.FsUserMixin):
        pass

    class WebAuthn(db.Model, fsqla.FsWebAuthnMixin):
        pass

    # Setup Flask-Security
    user_datastore = SQLAlchemyUserDatastore(db, User, Role, WebAuthn)
    app.security = Security(
        app,
        user_datastore,
        webauthn_util_cls=TestWebauthnUtil,
        mail_util_cls=FlashMailUtil,
    )

    try:
        import flask_babel

        babel = flask_babel.Babel(app)
    except ImportError:
        try:
            import flask_babelex

            babel = flask_babelex.Babel(app)
        except ImportError:
            babel = None

    if babel:

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

        babel.locale_selector = get_locale

    @app.after_request
    def allow_absolute_redirect(r):
        # This is JUST to test odd possible redirects that look relative but are
        # interpreted by browsers as absolute.
        # DON'T SET THIS IN YOUR APPLICATION!
        r.autocorrect_location_header = False
        return r

    @user_registered.connect_via(app)
    def on_user_registered(myapp, user, confirm_token, **extra):
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
    @login_required
    def home():
        return render_template_string(
            """
            {% include 'security/_messages.html' %}
            {{ _fsdomain('Welcome') }} {{email}} !
            {% include "security/_menu.html" %}
            """,
            email=current_user.email,
            security=app.security,
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


def add_user(ds, email, password, roles):
    pw = hash_password(password)
    roles = [ds.find_or_create_role(rn) for rn in roles]
    ds.commit()
    user = ds.create_user(
        email=email, password=pw, active=True, confirmed_at=datetime.datetime.utcnow()
    )
    ds.commit()
    for role in roles:
        ds.add_role_to_user(user, role)
    ds.commit()


if __name__ == "__main__":
    myapp = create_app()

    with myapp.app_context():
        myapp.security.datastore.db.create_all()
        test_acct = "test@test.com"
        if not myapp.security.datastore.find_user(email=test_acct):
            add_user(myapp.security.datastore, test_acct, "password", ["admin"])
            print("Created User: {} with password {}".format(test_acct, "password"))

    myapp.run(port=5001)
