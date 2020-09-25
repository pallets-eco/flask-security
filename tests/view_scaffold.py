# :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
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

from flask import Flask, flash, render_template_string, request, session

HAVE_BABEL = HAVE_BABELEX = False
try:
    import flask_babel

    HAVE_BABEL = True
except ImportError:
    try:
        import flask_babelex

        HAVE_BABELEX = True
    except ImportError:
        pass


from flask.json import JSONEncoder
from flask_security import (
    Security,
    auth_required,
    current_user,
    login_required,
    SQLAlchemySessionUserDatastore,
)
from flask_security.signals import (
    us_security_token_sent,
    tf_security_token_sent,
    reset_password_instructions_sent,
    user_registered,
)
from flask_security.utils import hash_password, uia_email_mapper, uia_phone_mapper


def _find_bool(v):
    if str(v).lower() in ["true"]:
        return True
    elif str(v).lower() in ["false"]:
        return False
    return v


class FlashMail:
    def __init__(self, app):
        app.extensions["mail"] = self

    def send(self, msg):
        flash(msg.body)


def create_app():
    # Use real templates - not test templates...
    app = Flask(__name__, template_folder="../")
    app.config["DEBUG"] = True
    # SECRET_KEY generated using: secrets.token_urlsafe()
    app.config["SECRET_KEY"] = "pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw"
    # PASSWORD_SALT secrets.SystemRandom().getrandbits(128)
    app.config["SECURITY_PASSWORD_SALT"] = "156043940537155509276282232127182067465"

    app.config["LOGIN_DISABLED"] = False
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"] = [
        {"email": {"mapper": uia_email_mapper, "case_insensitive": True}},
        {"us_phone_number": {"mapper": uia_phone_mapper}},
    ]
    # app.config["SECURITY_US_ENABLED_METHODS"] = ["password"]
    # app.config["SECURITY_US_ENABLED_METHODS"] = ["authenticator", "password"]

    # app.config["SECURITY_US_SIGNIN_REPLACES_LOGIN"] = True

    app.config["SECURITY_TOTP_SECRETS"] = {
        "1": "TjQ9Qa31VOrfEzuPy4VHQWPCTmRzCnFzMKLxXYiZu9B"
    }
    app.config["SECURITY_FRESHNESS"] = datetime.timedelta(minutes=0.5)
    app.config["SECURITY_FRESHNESS_GRACE_PERIOD"] = datetime.timedelta(minutes=2)

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
    ]:
        app.config["SECURITY_" + opt.upper()] = True

    if os.environ.get("SETTINGS"):
        # Load settings from a file pointed to by SETTINGS
        app.config.from_envvar("SETTINGS")
    # Allow any SECURITY_ config to be set in environment.
    for ev in os.environ:
        if ev.startswith("SECURITY_"):
            app.config[ev] = _find_bool(os.environ.get(ev))
    mail = FlashMail(app)
    app.mail = mail

    app.json_encoder = JSONEncoder
    # Setup Flask-Security
    user_datastore = SQLAlchemySessionUserDatastore(db_session, User, Role)
    Security(app, user_datastore)

    babel = None
    if HAVE_BABEL:
        babel = flask_babel.Babel(app)
    if HAVE_BABELEX:
        babel = flask_babelex.Babel(app)

    if babel:

        @babel.localeselector
        def get_locale():
            # For a given session - set lang based on first request.
            # Honor explicit url request first
            if "lang" not in session:
                locale = request.args.get("lang", None)
                if not locale:
                    locale = request.accept_languages.best
                if not locale:
                    locale = "en"
                if locale:
                    session["lang"] = locale
            return session.get("lang", None).replace("-", "_")

    # Create a user to test with
    @app.before_first_request
    def create_user():
        init_db()
        db_session.commit()
        test_acct = "test@test.com"
        if not user_datastore.find_user(email=test_acct):
            add_user(user_datastore, test_acct, "password", ["admin"])
            print("Created User: {} with password {}".format(test_acct, "password"))

    @user_registered.connect_via(app)
    def on_user_registered(myapp, user, confirm_token, **extra):
        flash(f"To confirm {user.email} - go to /confirm/{confirm_token}")

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
            "{% include 'security/_messages.html' %}"
            "{{ _fsdomain('Welcome') }} {{email}} !",
            email=current_user.email,
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


"""

Datastore

"""

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

engine = create_engine("sqlite:////tmp/view_scaffold.db?check_same_thread=False")
db_session = scoped_session(
    sessionmaker(autocommit=False, autoflush=False, bind=engine)
)
Base = declarative_base()
Base.query = db_session.query_property()


def init_db():
    # import all modules here that might define models so that
    # they will be registered properly on the metadata.  Otherwise
    # you will have to import them first before calling init_db()
    Base.metadata.create_all(bind=engine)


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


"""

Required Models

"""

from flask_security import UserMixin, RoleMixin
from sqlalchemy.orm import relationship, backref
from sqlalchemy import Boolean, DateTime, Column, Integer, String, Text, ForeignKey


class RolesUsers(Base):
    __tablename__ = "roles_users"
    id = Column(Integer(), primary_key=True)
    user_id = Column("user_id", Integer(), ForeignKey("user.id"))
    role_id = Column("role_id", Integer(), ForeignKey("role.id"))


class Role(Base, RoleMixin):
    __tablename__ = "role"
    id = Column(Integer(), primary_key=True)
    name = Column(String(80), unique=True)
    description = Column(String(255))


class User(Base, UserMixin):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    fs_uniquifier = Column(String(64), unique=True, nullable=False)
    email = Column(String(255), unique=True)
    username = Column(String(255), unique=True, nullable=True)
    password = Column(String(255), nullable=False)
    last_login_at = Column(DateTime())
    current_login_at = Column(DateTime())
    last_login_ip = Column(String(100))
    current_login_ip = Column(String(100))
    login_count = Column(Integer)
    active = Column(Boolean())
    confirmed_at = Column(DateTime())

    tf_phone_number = Column(String(128))
    tf_primary_method = Column(String(64))
    tf_totp_secret = Column(String(255))

    us_totp_secrets = Column(Text(), nullable=True)
    us_phone_number = Column(String(128), nullable=True)

    roles = relationship(
        "Role", secondary="roles_users", backref=backref("users", lazy="dynamic")
    )


if __name__ == "__main__":
    create_app().run(port=5001)
