# :copyright: (c) 2019 by J. Christopher Wagner (jwag).
# :license: MIT, see LICENSE for more details.

"""
This is simple scaffold that can be run as an app and manually test
various views using a browser.

Configurations can be set via environment variables.

Runs on port 5001

In order to start - you need to register a user.
To confirm - take the token printed on the console - and put that in your browser
at /confirm/{token}


Since we don't actually send email - we have signal handlers dump the required
data to the console.

"""

import datetime
import os

from flask import Flask, render_template_string, request, session
import flask_babelex
from flask_mail import Mail
from flask.json import JSONEncoder
from flask_security import (
    Security,
    current_user,
    login_required,
    SQLAlchemySessionUserDatastore,
)
from flask_security.signals import (
    tf_security_token_sent,
    reset_password_instructions_sent,
    user_registered,
)
from flask_security.utils import hash_password


def create_app():
    app = Flask(__name__)
    app.config["DEBUG"] = True
    app.config["SECRET_KEY"] = "super-secret"
    app.config["LOGIN_DISABLED"] = False
    app.config["WTF_CSRF_ENABLED"] = False
    # Don't actually send any email - instead we subscribe to signals
    # and print out required info.
    app.config["MAIL_SUPPRESS_SEND"] = True
    app.config["SECURITY_TWO_FACTOR_SECRET"] = {
        "1": "TjQ9Qa31VOrfEzuPy4VHQWPCTmRzCnFzMKLxXYiZu9B"
    }

    app.config["SECURITY_PASSWORD_SALT"] = "salty"
    # Make this plaintext for most tests - reduces unit test time by 50%
    app.config["SECURITY_PASSWORD_HASH"] = "plaintext"
    # Make this hex_md5 for token tests
    app.config["SECURITY_HASHING_SCHEMES"] = ["hex_md5"]
    app.config["SECURITY_DEPRECATED_HASHING_SCHEMES"] = []

    for opt in [
        "changeable",
        "recoverable",
        "registerable",
        "trackable",
        "NOTpasswordless",
        "confirmable",
        "two_factor",
    ]:
        app.config["SECURITY_" + opt.upper()] = True

    if os.environ.get("SETTINGS"):
        app.config.from_envvar("SETTINGS")
    mail = Mail(app)

    app.json_encoder = JSONEncoder
    app.mail = mail
    # Setup Flask-Security
    user_datastore = SQLAlchemySessionUserDatastore(db_session, User, Role)
    security = Security(app, user_datastore)

    # This is NOT ideal since it basically changes entire APP (which is fine for
    # this test - but not fine for general use).
    babel = flask_babelex.Babel(app, default_domain=security.i18n_domain)

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
        if not user_datastore.get_user(test_acct):
            add_user(user_datastore, test_acct, "password", ["admin"])
            print("Created User: {} with password {}".format(test_acct, "password"))

    @user_registered.connect_via(app)
    def on_user_registerd(myapp, user, confirm_token):
        print("User {} registered with token {}".format(user.email, confirm_token))

    @reset_password_instructions_sent.connect_via(app)
    def on_reset(myapp, user, token):
        print("User {} started password reset with token {}".format(user.email, token))

    @tf_security_token_sent.connect_via(app)
    def on_token_sent(myapp, user, token, method):
        print(
            "User {} was sent two factor token {} via {}".format(
                user.email, token, method
            )
        )

    # Views
    @app.route("/")
    @login_required
    def home():
        return render_template_string(
            "{{ _('Welcome') }} {{email}} !", email=current_user.email
        )

    return app


"""

Datastore

"""

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

engine = create_engine(
    "sqlite:////tmp/view_scaffold.db?check_same_thread=False", convert_unicode=True
)
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
from sqlalchemy import Boolean, DateTime, Column, Integer, String, ForeignKey


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
    email = Column(String(255), unique=True)
    username = Column(String(255))
    password = Column(String(255))
    last_login_at = Column(DateTime())
    current_login_at = Column(DateTime())
    last_login_ip = Column(String(100))
    current_login_ip = Column(String(100))
    login_count = Column(Integer)
    active = Column(Boolean())
    confirmed_at = Column(DateTime())

    tf_phone_number = Column(String(64))
    tf_primary_method = Column(String(140))
    tf_totp_secret = Column(String(255))

    roles = relationship(
        "Role", secondary="roles_users", backref=backref("users", lazy="dynamic")
    )


if __name__ == "__main__":
    create_app().run(port=5001)
