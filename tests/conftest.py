"""
conftest
~~~~~~~~

Test fixtures and what not

:copyright: (c) 2017 by CERN.
:copyright: (c) 2019-2025 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.
"""

from __future__ import annotations

import sqlite3
import gc
import os
import tempfile
import time
import typing as t
from datetime import datetime
import sys
from urllib.parse import urlsplit

from passlib.ifc import PasswordHash
from passlib.registry import register_crypt_handler
import pytest
from flask import Flask, Response, jsonify, render_template
from flask import request as flask_request
from flask_mailman import Mail
from flask_wtf import CSRFProtect

try:
    from sqlalchemy.orm import Mapped
except ImportError:
    pass

from flask_security import (
    FSQLALiteUserDatastore,
    MongoEngineUserDatastore,
    PeeweeUserDatastore,
    PonyUserDatastore,
    RoleMixin,
    Security,
    SQLAlchemySessionUserDatastore,
    SQLAlchemyUserDatastore,
    UserMixin,
    WebAuthnMixin,
    auth_required,
    auth_token_required,
    http_auth_required,
    get_request_attr,
    roles_accepted,
    roles_required,
    permissions_accepted,
    permissions_required,
    uia_email_mapper,
)
from flask_security.utils import localize_callback

from tests.test_utils import convert_bool_option, populate_data

NO_BABEL = False
try:
    from flask_babel import Babel
except ImportError:
    NO_BABEL = True


class FastHash(PasswordHash):
    """Our own 'hasher'. For testing
    we want a fast hash, but a real one such that the provided password
    and hash aren't the same (which is what happens when using plaintext).
    """

    name = "fasthash"
    setting_kwds = ()
    context_kwds = ()

    @classmethod
    def hash(cls, secret, **kwds):
        return f"$fh$1${secret}"

    @classmethod
    def verify(cls, secret, stored_hash, **context_kwds):
        new_hash = f"$fh$1${secret}"
        return new_hash == stored_hash

    @classmethod
    def identify(cls, stored_hash):
        return stored_hash.startswith("$fh$1$")

    @classmethod
    def using(cls, relaxed=False, **settings):
        return type("fasthash2", (cls,), {})


# python 3.13 is strict about not closing sqlite3 db connections.
def find_sqlite_connections():
    connections = []
    for obj in gc.get_objects():
        if isinstance(obj, sqlite3.Connection):
            connections.append(obj)
    return connections


@pytest.fixture()
def app(request):
    # assert not find_sqlite_connections()  # hopefully find tests that don't clean up
    app = Flask(__name__)
    app.response_class = Response
    app.debug = True
    app.config["SECRET_KEY"] = "secret"
    app.config["TESTING"] = True
    app.config["LOGIN_DISABLED"] = False
    app.config["WTF_CSRF_ENABLED"] = False
    # Our test emails/domain isn't necessarily valid
    app.config["SECURITY_EMAIL_VALIDATOR_ARGS"] = {"check_deliverability": False}
    app.config["SECURITY_TOTP_SECRETS"] = {
        "1": "TjQ9Qa31VOrfEzuPy4VHQWPCTmRzCnFzMKLxXYiZu9B"
    }
    app.config["SECURITY_TOTP_ISSUER"] = "tests"
    app.config["SECURITY_SMS_SERVICE"] = "test"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    app.config["SECURITY_PASSWORD_SALT"] = "salty"
    app.config["SECURITY_CONFIRM_SALT"] = "confirm-salty"
    # Make this fasthash for most tests - reduces unit test time by 50%
    app.config["SECURITY_PASSWORD_SCHEMES"] = ["fasthash", "argon2", "bcrypt"]
    app.config["SECURITY_PASSWORD_HASH"] = "fasthash"
    app.config["SECURITY_PASSWORD_SINGLE_HASH"] = True
    register_crypt_handler(FastHash)
    # Make this hex_md5 for token tests
    app.config["SECURITY_HASHING_SCHEMES"] = ["hex_md5"]
    app.config["SECURITY_DEPRECATED_HASHING_SCHEMES"] = []
    app.fs_constructor_args = (
        dict()
    )  # allow marks to set items for Security constructor

    for opt in [
        "changeable",
        "change_email",
        "change_username",
        "confirmable",
        "passwordless",
        "recoverable",
        "registerable",
        "trackable",
        "two_factor",
        "unified_signin",
        "username_recovery",
        "webauthn",
    ]:
        app.config["SECURITY_" + opt.upper()] = opt in request.keywords

    marker_getter = request.node.get_closest_marker

    # Import webauthn, or skip test if webauthn isn't installed
    webauthn_test = marker_getter("webauthn")
    if webauthn_test is not None:
        pytest.importorskip("webauthn")
        app.fs_constructor_args.update(**webauthn_test.kwargs)

    oauthlib_test = marker_getter("oauth")
    if oauthlib_test is not None:
        pytest.importorskip("authlib")

    mfa_test = marker_getter("two_factor") or marker_getter("unified_signin")
    if mfa_test is not None:
        pytest.importorskip("cryptography")

    flask_async_test = marker_getter("flask_async")
    if flask_async_test is not None:
        pytest.importorskip("asgiref")  # from flask[async]

    # Override config settings as requested for this test
    settings = marker_getter("settings")
    if settings is not None:
        for key, value in settings.kwargs.items():
            app.config["SECURITY_" + key.upper()] = value
    settings = marker_getter("app_settings")
    if settings is not None:
        for key, value in settings.kwargs.items():
            app.config[key.upper()] = value

    # allow pytest command line to override everything
    if request.config.option.setting:
        for s in request.config.option.setting:
            key, value = s.split("=")
            app.config[key.upper()] = convert_bool_option(value)

    app.mail = Mail(app)  # type: ignore

    # use babel marker to signify tests that need babel extension.
    babel = marker_getter("babel")
    if babel:
        if NO_BABEL:
            raise pytest.skip("Requires Babel")
        Babel(app)

    csrf = marker_getter("csrf")
    if csrf is not None:
        # without any keys/arguments - this is the default config
        # Note that WTF_CSRF_CHECK_DEFAULT = True means Flask_wtf will
        # run a CSRF check as part of @before_request - before we see it.
        app.config["WTF_CSRF_ENABLED"] = True
        if "ignore_unauth" in csrf.kwargs.keys():
            app.config["WTF_CSRF_CHECK_DEFAULT"] = False
            app.config["SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS"] = True
        if "csrfprotect" in csrf.kwargs.keys():
            # This is needed when passing CSRF in header or non-form input
            app.config["WTF_CSRF_CHECK_DEFAULT"] = False
            CSRFProtect(app)

    @app.route("/")
    def index():
        return render_template("index.html", content="Home Page")

    @app.route("/profile")
    @auth_required()
    def profile():
        if hasattr(app, "security"):
            if app.security._want_json(flask_request):
                return jsonify(message="profile")

        return render_template("index.html", content="Profile Page")

    @app.route("/post_login")
    @auth_required()
    def post_login():
        return render_template("index.html", content="Post Login")

    @app.route("/http", methods=["GET", "POST"])
    @http_auth_required
    def http():
        return "HTTP Authentication"

    @app.route("/http_admin_required")
    @http_auth_required
    @permissions_required("admin")
    def http_admin_required():
        assert get_request_attr("fs_authn_via") == "basic"
        return "HTTP Authentication"

    @app.route("/http_custom_realm")
    @http_auth_required("My Realm")
    def http_custom_realm():
        assert get_request_attr("fs_authn_via") == "basic"
        return render_template("index.html", content="HTTP Authentication")

    @app.route("/session")
    @auth_required("session")
    def session():
        return "Session Authentication"

    @app.route("/token", methods=["GET", "POST"])
    @auth_token_required
    def token():
        assert get_request_attr("fs_authn_via") == "token"
        return render_template("index.html", content="Token Authentication")

    @app.route("/multi_auth")
    @auth_required("session", "token", "basic")
    def multi_auth():
        return render_template("index.html", content="Session, Token, Basic auth")

    @app.route("/post_logout")
    def post_logout():
        return render_template("index.html", content="Post Logout")

    @app.route("/post_register")
    def post_register():
        return render_template("index.html", content="Post Register")

    @app.route("/post_confirm")
    def post_confirm():
        return render_template("index.html", content="Post Confirm")

    @app.route("/post_reset")
    def post_reset():
        return render_template("index.html", content="Post Reset")

    @app.route("/post_change_username")
    def post_change_username():
        return render_template("index.html", content="Post Change Username")

    @app.route("/admin")
    @roles_required("admin")
    def admin():
        assert get_request_attr("fs_authn_via") == "session"
        return render_template("index.html", content="Admin Page")

    @app.route("/admin_and_editor")
    @roles_required("admin", "editor")
    def admin_and_editor():
        return render_template("index.html", content="Admin and Editor Page")

    @app.route("/admin_or_editor")
    @roles_accepted("admin", "editor")
    def admin_or_editor():
        return render_template("index.html", content="Admin or Editor Page")

    @app.route("/simple")
    @roles_accepted("simple")
    def simple():
        return render_template("index.html", content="SimplePage")

    @app.route("/admin_perm")
    @permissions_accepted("full-write", "super")
    def admin_perm():
        return render_template(
            "index.html", content="Admin Page with full-write or super"
        )

    @app.route("/admin_perm_required")
    @permissions_required("full-write", "super")
    def admin_perm_required():
        return render_template("index.html", content="Admin Page required")

    @app.route("/page1")
    def page_1():
        return "Page 1"

    @app.route("/json", methods=["GET", "POST"])
    def echo_json():
        return jsonify(flask_request.get_json())

    @app.route("/json_auth", methods=["POST"])
    @auth_required()
    def echo_jsonauth():
        return jsonify(flask_request.get_json())

    @app.route("/unauthz", methods=["GET", "POST"])
    def unauthz():
        return render_template("index.html", content="Unauthorized")

    @app.route("/fresh", methods=["GET", "POST"])
    @auth_required(within=60)
    def fresh():
        if app.security._want_json(flask_request):
            return jsonify(title="Fresh Only")
        else:
            return render_template("index.html", content="Fresh Only")

    def revert_forms():
        # Some forms/tests have dynamic fields - be sure to revert them.
        if hasattr(app, "security"):
            for form_name in [
                "login_form",
                "register_form",
                "confirm_register_form",
                "change_username_form",
            ]:
                if hasattr(app.security.forms[form_name].cls, "username"):
                    del app.security.forms[form_name].cls.username

        from flask_security import RegisterFormV2
        from flask_security.forms import PasswordConfirmFormMixin, NewPasswordFormMixin

        for attr in ["username"]:
            if hasattr(RegisterFormV2, attr):
                delattr(RegisterFormV2, attr)
        RegisterFormV2.password_confirm = PasswordConfirmFormMixin.password_confirm
        RegisterFormV2.password = NewPasswordFormMixin.password

    request.addfinalizer(revert_forms)
    yield app
    # help find tests that don't clean up - note that pony leaves a connection so
    # we can't use this in 'production'...
    # assert not find_sqlite_connections()


@pytest.fixture()
def mongoengine_datastore(app, tmpdir, realmongodburl):
    ds, td = mongoengine_setup(app, tmpdir, realmongodburl)
    yield ds
    td()


def mongoengine_setup(app, tmpdir, realmongodburl):
    # To run against a realdb: mongod --dbpath <somewhere>
    import pymongo
    import mongomock
    from mongoengine import Document, connect
    from mongoengine.fields import (
        BinaryField,
        BooleanField,
        DateTimeField,
        IntField,
        ListField,
        ReferenceField,
        StringField,
    )
    from mongoengine import PULL, CASCADE, disconnect_all

    db_name = "flask_security_test"
    db_host = realmongodburl if realmongodburl else "mongodb://localhost"
    db_client_class = pymongo.MongoClient if realmongodburl else mongomock.MongoClient
    db = connect(
        alias=db_name,
        db=db_name,
        host=db_host,
        port=27017,
        mongo_client_class=db_client_class,
    )

    class Role(Document, RoleMixin):
        name = StringField(required=True, unique=True, max_length=80)
        description = StringField(max_length=255)
        permissions = ListField(required=False)
        meta = {"db_alias": db_name}

    class WebAuthn(Document, WebAuthnMixin):
        credential_id = BinaryField(primary_key=True, max_bytes=1024, required=True)
        public_key = BinaryField(required=True)
        sign_count = IntField(default=0)
        transports = ListField(required=False)
        backup_state = BooleanField(required=True)
        device_type = StringField(max_length=64, required=True)

        # a JSON string as returned from registration
        extensions = StringField(max_length=255)
        lastuse_datetime = DateTimeField(required=True)
        # name is provided by user - we make sure it is unique per user
        name = StringField(max_length=64, required=True)
        usage = StringField(max_length=64, required=True)
        # we need to be able to look up a user from a credential_id
        user = ReferenceField("User")
        # user_id = ObjectIdField(required=True)
        meta = {"db_alias": db_name}

        def get_user_mapping(self) -> dict[str, str]:
            """
            Return the mapping from webauthn back to User
            """
            return dict(id=self.user.id)

    class User(Document, UserMixin):
        email = StringField(unique=True, max_length=255)
        fs_uniquifier = StringField(unique=True, max_length=64, required=True)
        fs_webauthn_user_handle = StringField(unique=True, max_length=64)
        username = StringField(unique=True, required=False, sparse=True, max_length=255)
        password = StringField(required=False, max_length=255)
        security_number = IntField(unique=True, required=False, sparse=True)
        last_login_at = DateTimeField()
        current_login_at = DateTimeField()
        tf_primary_method = StringField(max_length=255)
        tf_totp_secret = StringField(max_length=255)
        tf_phone_number = StringField(max_length=255)
        mf_recovery_codes = ListField(required=False)
        us_totp_secrets = StringField()
        us_phone_number = StringField(
            max_length=255, unique=True, required=False, sparse=True
        )
        last_login_ip = StringField(max_length=100)
        current_login_ip = StringField(max_length=100)
        login_count = IntField()
        active = BooleanField(default=True)
        confirmed_at = DateTimeField()
        roles = ListField(ReferenceField(Role), default=[])
        webauthn = ListField(
            ReferenceField(WebAuthn, reverse_delete_rule=PULL), default=[]
        )
        meta = {"db_alias": db_name}

        def get_security_payload(self):
            return {"email": str(self.email)}

    User.register_delete_rule(WebAuthn, "user", CASCADE)

    def tear_down():
        with app.app_context():
            User.drop_collection()
            Role.drop_collection()
            WebAuthn.drop_collection()
            db.drop_database(db_name)
            disconnect_all()

    return MongoEngineUserDatastore(db, User, Role, WebAuthn), tear_down


@pytest.fixture()
def sqlalchemy_datastore(app, tmpdir, realdburl):
    ds, td = sqlalchemy_setup(app, tmpdir, realdburl)
    yield ds
    td()


def sqlalchemy_setup(app, tmpdir, realdburl):
    pytest.importorskip("flask_sqlalchemy")
    from flask_sqlalchemy import SQLAlchemy
    from sqlalchemy import Column, Integer
    from flask_security.models import fsqla_v3 as fsqla

    if realdburl:
        db_url, db_info = _setup_realdb(realdburl)
        app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

    # In Flask-SQLAlchemy >= 3.0.0 queries are no longer logged automatically,
    # even in debug or testing mode.
    app.config["SQLALCHEMY_RECORD_QUERIES"] = True

    db = SQLAlchemy(app)

    fsqla.FsModels.set_db_info(db)

    class Role(db.Model, fsqla.FsRoleMixin):
        pass

    class WebAuthn(db.Model, fsqla.FsWebAuthnMixin):
        pass

    class User(db.Model, fsqla.FsUserMixin):
        security_number = Column(Integer, unique=True)

        def get_security_payload(self):
            # Make sure we still properly hook up to flask's JSON extension
            # which handles datetime
            return {"email": str(self.email), "last_update": self.update_datetime}

        def augment_auth_token(self, tdata):
            # for testing - if TESTING_AUGMENT_AUTH_TOKEN is set - call that
            from flask import current_app

            if cb := current_app.config.get("TESTING_AUGMENT_AUTH_TOKEN"):
                cb(tdata)

    with app.app_context():
        db.create_all()

    def tear_down():
        with app.app_context():
            if realdburl:
                db.drop_all()
                _teardown_realdb(db_info)
            engine = db.engine
            engine.dispose()

    return SQLAlchemyUserDatastore(db, User, Role, WebAuthn), tear_down


@pytest.fixture()
def fsqlalite_datastore(app, tmpdir, realdburl):
    ds, td = fsqlalite_setup(app, tmpdir, realdburl)
    yield ds
    td()


@pytest.fixture()
def fsqlalite_min_datastore(app, tmpdir, realdburl):
    pytest.importorskip("flask_sqlalchemy_lite")
    from sqlalchemy.orm import declared_attr, mapped_column, relationship
    from sqlalchemy import String

    class FsMinUserMixin(UserMixin):
        # flask_security basic fields
        id: Mapped[int] = mapped_column(primary_key=True)  # type: ignore
        email: Mapped[str] = mapped_column(String(255), unique=True)  # type: ignore
        password: Mapped[str | None] = mapped_column(String(255))  # type: ignore
        active: Mapped[bool] = mapped_column()  # type: ignore
        fs_uniquifier: Mapped[str] = mapped_column(  # type: ignore
            String(64), unique=True
        )

        @declared_attr
        def roles(cls):
            # The first arg is a class name, the backref is a column name
            return relationship(
                "Role",
                secondary="roles_users",
                back_populates="users",
            )

    ds, td = fsqlalite_setup(
        app, tmpdir, realdburl, usermixin=FsMinUserMixin, use_webauthn=False
    )
    yield ds
    td()


def fsqlalite_setup(app, tmpdir, realdburl, usermixin=None, use_webauthn=True):
    pytest.importorskip("flask_sqlalchemy_lite")
    from flask_sqlalchemy_lite import SQLAlchemy
    from sqlalchemy.orm import DeclarativeBase, mapped_column
    from flask_security.models import sqla as sqla

    if not usermixin:
        usermixin = sqla.FsUserMixin
    if realdburl:
        db_url, db_info = _setup_realdb(realdburl)
    else:
        db_url = "sqlite:///:memory:"
    app.config |= {
        "SQLALCHEMY_ENGINES": {
            "default": {"url": db_url, "pool_pre_ping": True},
        },
    }
    db = SQLAlchemy(app)

    class Model(DeclarativeBase):
        pass

    sqla.FsModels.set_db_info(base_model=Model)

    class Role(Model, sqla.FsRoleMixin):
        __tablename__ = "role"

    if use_webauthn:

        class WebAuthn(Model, sqla.FsWebAuthnMixin):
            __tablename__ = "webauthn"

    class User(Model, usermixin):
        __tablename__ = "user"
        security_number: Mapped[t.Optional[int]] = mapped_column(  # type: ignore
            unique=True
        )

        def get_security_payload(self) -> dict[str, t.Any]:
            # Make sure we still properly hook up to flask's JSON extension
            # which handles datetime
            return {"email": str(self.email), "last_update": self.update_datetime}

    with app.app_context():
        Model.metadata.create_all(db.engine)

    def tear_down():
        with app.app_context():
            Model.metadata.drop_all(db.engine)
            engine = db.engine
            engine.dispose()
            if realdburl:
                _teardown_realdb(db_info)

    return (
        FSQLALiteUserDatastore(db, User, Role, WebAuthn if use_webauthn else None),
        tear_down,
    )


@pytest.fixture()
def sqlalchemy_session_datastore(app, tmpdir, realdburl):
    if sys.version_info < (3, 10):
        pytest.skip("requires python3.10 or higher")
    ds, td = sqlalchemy_session_setup(app, tmpdir, realdburl)
    yield ds
    td()


def sqlalchemy_session_setup(app, tmpdir, realdburl, **engine_kwargs):
    """
    Note that we test having a different user id column name here.
    """
    pytest.importorskip("sqlalchemy")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import (
        mapped_column,
        scoped_session,
        sessionmaker,
        declarative_base,
    )
    from sqlalchemy.ext.declarative import declared_attr
    from sqlalchemy import (
        Column,
        Integer,
        ForeignKey,
    )
    from flask_security.models import sqla as sqla

    if realdburl:
        db_url, db_info = _setup_realdb(realdburl)
        engine = db_info["engine"]
    else:
        db_url = "sqlite:///:memory:"
        engine = create_engine(db_url, **engine_kwargs)

    db_session = scoped_session(
        sessionmaker(autocommit=False, autoflush=False, bind=engine)
    )
    app.teardown_appcontext(lambda exc: db_session.close())
    Base = declarative_base()
    # Note that in this case we don't call set_db_info since we are using
    # normal table names AND we need our own RolesUsers table since we modified the
    # PK names.

    class WebAuthn(Base, sqla.FsWebAuthnMixin):
        __tablename__ = "webauthn"

        @declared_attr
        def user_id(self) -> Mapped[int]:
            return mapped_column(ForeignKey("user.myuserid", ondelete="CASCADE"))

        def get_user_mapping(self) -> dict[str, t.Any]:
            """
            Return the filter needed by find_user() to get the user
            associated with this webauthn credential.
            """
            return dict(myuserid=self.user_id)

    class RolesUsers(Base):
        __tablename__ = "roles_users"
        id = Column(Integer(), primary_key=True)
        user_id = Column("user_id", Integer(), ForeignKey("user.myuserid"))
        role_id = Column("role_id", Integer(), ForeignKey("role.myroleid"))

    class Role(Base, sqla.FsRoleMixin):
        __tablename__ = "role"
        myroleid: Mapped[int] = mapped_column(primary_key=True)  # type: ignore
        id: Mapped[int] = mapped_column(nullable=True)  # type: ignore

    class User(Base, sqla.FsUserMixin):
        __tablename__ = "user"
        myuserid: Mapped[int] = mapped_column(primary_key=True)  # type: ignore
        id: Mapped[int] = mapped_column(nullable=True)  # type: ignore
        security_number: Mapped[t.Optional[int]] = mapped_column(  # type: ignore
            unique=True
        )

        def get_security_payload(self):
            # Make sure we still properly hook up to flask's JSON extension
            # which handles datetime
            return {"email": str(self.email), "last_update": self.update_datetime}

    with app.app_context():
        Base.metadata.create_all(bind=engine)

    def tear_down():
        with app.app_context():
            Base.metadata.drop_all(bind=engine)
            engine.dispose()
            if realdburl:
                _teardown_realdb(db_info)

    return SQLAlchemySessionUserDatastore(db_session, User, Role, WebAuthn), tear_down


@pytest.fixture()
def peewee_datastore(app, tmpdir, realdburl):
    ds, td = peewee_setup(app, tmpdir, realdburl)
    yield ds
    td()


def peewee_setup(app, tmpdir, realdburl):
    pytest.importorskip("peewee")
    from peewee import (
        TextField,
        DateTimeField,
        Field,
        IntegerField,
        BooleanField,
        BlobField,
        ForeignKeyField,
        CharField,
    )
    from playhouse.flask_utils import FlaskDB

    if realdburl:
        engine_mapper = {
            "postgresql": "peewee.PostgresqlDatabase",
            "mysql": "peewee.MySQLDatabase",
        }
        db_url, db_info = _setup_realdb(realdburl)
        pieces = urlsplit(db_url)
        db_config = {
            "name": pieces.path[1:],
            "engine": engine_mapper[pieces.scheme.split("+")[0]],
            "user": pieces.username,
            "password": pieces.password,
            "host": pieces.hostname,
            "port": pieces.port,
        }
    else:
        f, path = tempfile.mkstemp(
            prefix="flask-security-test-db", suffix=".db", dir=str(tmpdir)
        )
        db_config = {"name": path, "engine": "peewee.SqliteDatabase"}

    app.config["DATABASE"] = db_config

    db = FlaskDB(app)

    class AsaList(Field):
        field_type = "text"

        def db_value(self, value):
            try:
                return ",".join(value)
            except TypeError:
                return value

        def python_value(self, value):
            if value:
                return value.split(",")
            return []

    class Role(RoleMixin, db.Model):
        name = CharField(unique=True, max_length=80)
        description = TextField(null=True)
        permissions = AsaList(null=True)

    class User(UserMixin, db.Model):
        email = TextField(unique=True, null=False)
        fs_uniquifier = TextField(unique=True, null=False)
        fs_webauthn_user_handle = TextField(unique=True, null=True)
        username = TextField(unique=True, null=True)
        security_number = IntegerField(null=True)
        password = TextField(null=True)
        last_login_at = DateTimeField(null=True)
        current_login_at = DateTimeField(null=True)
        tf_primary_method = TextField(null=True)
        tf_totp_secret = TextField(null=True)
        tf_phone_number = TextField(null=True)
        mf_recovery_codes = AsaList(null=True)
        us_totp_secrets = TextField(null=True)
        us_phone_number = TextField(null=True, unique=True)
        last_login_ip = TextField(null=True)
        current_login_ip = TextField(null=True)
        login_count = IntegerField(null=True)
        active = BooleanField(default=True)
        confirmed_at = DateTimeField(null=True)

        def get_security_payload(self):
            return {"email": str(self.email)}

    class WebAuthn(WebAuthnMixin, db.Model):
        credential_id = BlobField(unique=True, null=False, index=True)
        public_key = BlobField(null=False)
        sign_count = IntegerField(default=0)
        transports = AsaList(null=True)

        # a JSON string as returned from registration
        extensions = TextField(null=True)
        lastuse_datetime = DateTimeField(null=False)
        # name is provided by user - we make sure is unique per user
        name = TextField(null=False)
        usage = TextField(null=False)
        backup_state = BooleanField()
        device_type = TextField(null=False)

        # This creates a real column called user_id
        user = ForeignKeyField(User, backref="webauthn")

    class UserRoles(db.Model):
        """Peewee does not have built-in many-to-many support, so we have to
        create this mapping class to link users to roles."""

        user = ForeignKeyField(User, backref="roles")
        role = ForeignKeyField(Role, backref="users")
        name = property(lambda self: self.role.name)
        description = property(lambda self: self.role.description)

        def get_permissions(self):
            return self.role.get_permissions()

    with app.app_context():
        for Model in (Role, User, UserRoles, WebAuthn):
            Model.drop_table()
            Model.create_table()

    def tear_down():
        if realdburl:
            db.close_db(None)
            _teardown_realdb(db_info)
        else:
            db.close_db(None)
            os.close(f)
            os.remove(path)

    return PeeweeUserDatastore(db, User, Role, UserRoles, WebAuthn), tear_down


@pytest.fixture()
def pony_datastore(app, tmpdir, realdburl):
    ds, td = pony_setup(app, tmpdir, realdburl)
    yield ds
    td()


def pony_setup(app, tmpdir, realdburl):
    pytest.importorskip("pony")
    from pony.orm import Database, Optional, Required, Set
    from pony.orm.core import SetInstance

    SetInstance.append = SetInstance.add
    db = Database()

    class Role(db.Entity):
        name = Required(str, unique=True)
        description = Optional(str, nullable=True)
        users = Set(lambda: User)  # type: ignore

    class User(db.Entity):
        email = Required(str)
        fs_uniquifier = Required(str, nullable=False)
        username = Optional(str)
        security_number = Optional(int)
        password = Optional(str, nullable=True)
        last_login_at = Optional(datetime)
        current_login_at = Optional(datetime)
        tf_primary_method = Optional(str, nullable=True)
        tf_totp_secret = Optional(str, nullable=True)
        tf_phone_number = Optional(str, nullable=True)
        us_totp_secrets = Optional(str, nullable=True)
        us_phone_number = Optional(str, nullable=True)
        last_login_ip = Optional(str)
        current_login_ip = Optional(str)
        login_count = Optional(int)
        active = Required(bool, default=True)
        confirmed_at = Optional(datetime)
        roles = Set(lambda: Role)

        def has_role(self, name):
            return name in {r.name for r in self.roles.copy()}

    if realdburl:
        db_url, db_info = _setup_realdb(realdburl)
        pieces = urlsplit(db_url)
        provider = pieces.scheme.split("+")[0]
        provider = "postgres" if provider == "postgresql" else provider
        db.bind(
            provider=provider,
            user=pieces.username,
            password=pieces.password,
            host=pieces.hostname,
            port=pieces.port,
            database=pieces.path[1:],
        )
    else:
        app.config["DATABASE"] = {"name": ":memory:", "engine": "pony.SqliteDatabase"}
        db.bind("sqlite", ":memory:", create_db=True)

    db.generate_mapping(create_tables=True)

    def tear_down():
        db.disconnect()
        if realdburl:
            _teardown_realdb(db_info)

    return PonyUserDatastore(db, User, Role), tear_down


@pytest.fixture()
def client(request, app, sqlalchemy_datastore):
    app.security = Security(
        app, datastore=sqlalchemy_datastore, **app.fs_constructor_args
    )
    populate_data(app)
    return app.test_client()


@pytest.fixture()
def client_nc(request, app, sqlalchemy_datastore):
    # useful for testing token auth.
    # No Cookies for You!
    app.security = Security(app, datastore=sqlalchemy_datastore)
    populate_data(app)
    return app.test_client(use_cookies=False)


@pytest.fixture(
    params=[
        "cl-fsqlalchemy",
        "cl-sqla-session",
        "cl-mongo",
        "cl-peewee",
        "cl-fsqlalite",
    ]
)
def clients(request, app, tmpdir, realdburl, realmongodburl):
    if request.param == "cl-fsqlalchemy":
        ds, td = sqlalchemy_setup(app, tmpdir, realdburl)
    elif request.param == "cl-sqla-session":
        if sys.version_info < (3, 10):
            pytest.skip("requires python3.10 or higher")
        ds, td = sqlalchemy_session_setup(app, tmpdir, realdburl)
    elif request.param == "cl-mongo":
        ds, td = mongoengine_setup(app, tmpdir, realmongodburl)
    elif request.param == "cl-peewee":
        ds, td = peewee_setup(app, tmpdir, realdburl)
    elif request.param == "cl-pony":
        # Not working yet.
        ds, td = pony_setup(app, tmpdir, realdburl)
    elif request.param == "cl-fsqlalite":
        ds, td = fsqlalite_setup(app, tmpdir, realdburl)

    app.security = Security(app, datastore=ds, **app.fs_constructor_args)
    populate_data(app)
    if request.param == "cl-peewee":
        # peewee is insistent on a single connection?
        ds.db.close_db(None)
    yield app.test_client()
    td()


@pytest.fixture()
def in_app_context(request, app, sqlalchemy_datastore):
    app.security = Security(
        app, datastore=sqlalchemy_datastore, **app.fs_constructor_args
    )
    with app.app_context():
        yield app


@pytest.fixture()
def get_message(app: Flask) -> t.Callable[..., bytes]:
    def fn(key, **kwargs):
        rv = app.config["SECURITY_MSG_" + key][0] % kwargs
        return rv.encode("utf-8")

    return fn


@pytest.fixture()
def get_message_local(app):
    def fn(key, **kwargs):
        return localize_callback(app.config["SECURITY_MSG_" + key][0], **kwargs)

    return fn


@pytest.fixture(
    params=[
        "sqlalchemy",
        "sqlalchemy-session",
        "mongoengine",
        "peewee",
        "pony",
        "fsqlalite",
    ]
)
def datastore(request, app, tmpdir, realdburl, realmongodburl):
    if request.param == "sqlalchemy":
        ds, td = sqlalchemy_setup(app, tmpdir, realdburl)
    elif request.param == "sqlalchemy-session":
        ds, td = sqlalchemy_session_setup(app, tmpdir, realdburl)
    elif request.param == "mongoengine":
        ds, td = mongoengine_setup(app, tmpdir, realmongodburl)
    elif request.param == "peewee":
        ds, td = peewee_setup(app, tmpdir, realdburl)
    elif request.param == "pony":
        if sys.version_info >= (3, 13):
            pytest.skip("pony requires python3.12 or lower")
        ds, td = pony_setup(app, tmpdir, realdburl)
    elif request.param == "fsqlalite":
        ds, td = fsqlalite_setup(app, tmpdir, realdburl)
    yield ds
    td()


@pytest.fixture()
# def script_info(app, datastore): # Fix me when pony works
def script_info(app, sqlalchemy_datastore):
    from flask.cli import ScriptInfo

    def create_app():
        uia = [
            {"email": {"mapper": uia_email_mapper}},
            {"us_phone_number": {"mapper": lambda x: x}},
        ]

        app.config.update(**{"SECURITY_USER_IDENTITY_ATTRIBUTES": uia})
        app.security = Security(app, datastore=sqlalchemy_datastore)
        return app

    return ScriptInfo(create_app=create_app)


@pytest.fixture()
def script_info_min(app, fsqlalite_min_datastore):
    from flask.cli import ScriptInfo

    def create_app():
        app.security = Security(app, datastore=fsqlalite_min_datastore)
        return app

    return ScriptInfo(create_app=create_app)


def pytest_addoption(parser):
    parser.addoption(
        "--realdburl",
        action="store",
        default=None,
        help="""Set url for using real database for testing.
        For postgres: 'postgresql://user:password@host/')""",
    )
    parser.addoption(
        "--realmongodburl",
        action="store",
        default=None,
        help="""Set url for using real mongo database for testing.
        e.g. 'localhost'""",
    )
    parser.addoption(
        "--setting",
        default=None,
        action="append",
        help="""Set one or more SECURITY_ settings from command line.
        e.g. --setting anonymous_user_enable=False""",
    )


@pytest.fixture(scope="session")
def realdburl(request):
    """
    Support running datastore tests against a real DB.
    For example psycopg2 is very strict about types in queries
    compared to sqlite
    To use postgres you need to of course run a postgres instance on localhost
    then pass in an extra arg to pytest:
    --realdburl postgresql://<user>@localhost/
    For mysql same - just download and add a root password.
    --realdburl "mysql+pymysql://root:<password>@localhost/"
    """
    return request.config.option.realdburl


@pytest.fixture(scope="session")
def realmongodburl(request):
    """
    Support running datastore tests against a real Mongo DB.
    --realmongodburl "localhost"

    """
    return request.config.option.realmongodburl


def _setup_realdb(realdburl):
    """
    Called when we want to run unit tests against a real DB.
    This is useful since different DB drivers are pickier about queries etc.
    (such as pyscopg2 and postgres)
    """
    from sqlalchemy import create_engine
    from sqlalchemy_utils import database_exists, create_database

    db_name = "flask_security_test_%s" % str(time.time()).replace(".", "_")

    db_uri = realdburl + db_name
    engine = create_engine(db_uri)
    if not database_exists(engine.url):
        create_database(engine.url)
    print("Setting up real DB at " + db_uri)
    return db_uri, {"engine": engine}


def _teardown_realdb(db_info):
    from sqlalchemy_utils import drop_database

    drop_database(db_info["engine"].url)
