"""
    conftest
    ~~~~~~~~

    Test fixtures and what not

    :copyright: (c) 2017 by CERN.
    :license: MIT, see LICENSE for more details.
"""

import os
import tempfile
import time
from datetime import datetime
from urllib.parse import urlsplit

import pytest
from flask import Flask, Response, render_template
from flask import jsonify
from flask import request as flask_request
from flask.json import JSONEncoder
from flask_mail import Mail

from flask_security import (
    MongoEngineUserDatastore,
    PeeweeUserDatastore,
    PonyUserDatastore,
    RoleMixin,
    Security,
    SQLAlchemySessionUserDatastore,
    SQLAlchemyUserDatastore,
    UserMixin,
    auth_required,
    auth_token_required,
    http_auth_required,
    get_request_attr,
    login_required,
    roles_accepted,
    roles_required,
    permissions_accepted,
    permissions_required,
    uia_email_mapper,
)
from flask_security.utils import localize_callback

from tests.test_utils import populate_data

NO_BABEL = False
try:
    from flask_babel import Babel
except ImportError:
    try:
        from flask_babelex import Babel
    except ImportError:
        NO_BABEL = True


@pytest.fixture()
def app(request):
    app = Flask(__name__)
    app.response_class = Response
    app.debug = True
    app.config["SECRET_KEY"] = "secret"
    app.config["TESTING"] = True
    app.config["LOGIN_DISABLED"] = False
    app.config["WTF_CSRF_ENABLED"] = False
    # Our test emails/domain isn't necessarily valid
    app.config["SECURITY_EMAIL_VALIDATOR_ARGS"] = {"check_deliverability": False}
    app.config["SECURITY_TWO_FACTOR_SECRET"] = {
        "1": "TjQ9Qa31VOrfEzuPy4VHQWPCTmRzCnFzMKLxXYiZu9B"
    }
    app.config["SECURITY_SMS_SERVICE"] = "test"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

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
        "passwordless",
        "confirmable",
        "two_factor",
        "unified_signin",
    ]:
        app.config["SECURITY_" + opt.upper()] = opt in request.keywords

    pytest_major = int(pytest.__version__.split(".")[0])
    if pytest_major >= 4:
        marker_getter = request.node.get_closest_marker
    else:
        marker_getter = request.keywords.get
    settings = marker_getter("settings")
    babel = marker_getter("babel")
    if settings is not None:
        for key, value in settings.kwargs.items():
            app.config["SECURITY_" + key.upper()] = value

    mail = Mail(app)
    if not NO_BABEL and (babel is None or babel.args[0]):
        Babel(app)
    app.json_encoder = JSONEncoder
    app.mail = mail

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
    @login_required
    def post_login():
        return render_template("index.html", content="Post Login")

    @app.route("/http")
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

    @app.route("/unauthz", methods=["GET", "POST"])
    def unauthz():
        return render_template("index.html", content="Unauthorized")

    @app.route("/fresh", methods=["GET", "POST"])
    @auth_required(within=0)
    def fresh():
        if app.security._want_json(flask_request):
            return jsonify(title="Fresh Only")
        else:
            return render_template("index.html", content="Fresh Only")

    return app


@pytest.fixture()
def mongoengine_datastore(request, app, tmpdir, realdburl):
    return mongoengine_setup(request, app, tmpdir, realdburl)


def mongoengine_setup(request, app, tmpdir, realdburl):
    pytest.importorskip("flask_mongoengine")
    from flask_mongoengine import MongoEngine
    from mongoengine.fields import (
        BooleanField,
        DateTimeField,
        IntField,
        ListField,
        ReferenceField,
        StringField,
    )

    db_name = "flask_security_test_%s" % str(time.time()).replace(".", "_")
    app.config["MONGODB_SETTINGS"] = {
        "db": db_name,
        "host": "mongomock://localhost",
        "port": 27017,
        "alias": db_name,
    }

    db = MongoEngine(app)

    class Role(db.Document, RoleMixin):
        name = StringField(required=True, unique=True, max_length=80)
        description = StringField(max_length=255)
        permissions = StringField(max_length=255)
        meta = {"db_alias": db_name}

    class User(db.Document, UserMixin):
        email = StringField(unique=True, max_length=255)
        fs_uniquifier = StringField(unique=True, max_length=64, required=True)
        username = StringField(unique=True, required=False, sparse=True, max_length=255)
        password = StringField(required=False, max_length=255)
        security_number = IntField(unique=True, required=False, sparse=True)
        last_login_at = DateTimeField()
        current_login_at = DateTimeField()
        tf_primary_method = StringField(max_length=255)
        tf_totp_secret = StringField(max_length=255)
        tf_phone_number = StringField(max_length=255)
        us_totp_secrets = StringField()
        us_phone_number = StringField(max_length=255)
        last_login_ip = StringField(max_length=100)
        current_login_ip = StringField(max_length=100)
        login_count = IntField()
        active = BooleanField(default=True)
        confirmed_at = DateTimeField()
        roles = ListField(ReferenceField(Role), default=[])
        meta = {"db_alias": db_name}

    def tear_down():
        with app.app_context():
            User.drop_collection()
            Role.drop_collection()
            db.connection.drop_database(db_name)

    request.addfinalizer(tear_down)

    return MongoEngineUserDatastore(db, User, Role)


@pytest.fixture()
def sqlalchemy_datastore(request, app, tmpdir, realdburl):
    return sqlalchemy_setup(request, app, tmpdir, realdburl)


def sqlalchemy_setup(request, app, tmpdir, realdburl):
    pytest.importorskip("flask_sqlalchemy")
    from flask_sqlalchemy import SQLAlchemy
    from flask_security.models import fsqla_v2 as fsqla

    if realdburl:
        db_url, db_info = _setup_realdb(realdburl)
        app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

    db = SQLAlchemy(app)

    fsqla.FsModels.set_db_info(db)

    class Role(db.Model, fsqla.FsRoleMixin):
        pass

    class User(db.Model, fsqla.FsUserMixin):
        security_number = db.Column(db.Integer, unique=True)
        # For testing allow null passwords.
        password = db.Column(db.String(255), nullable=True)

        def get_security_payload(self):
            # Make sure we still properly hook up to flask JSONEncoder
            return {"email": str(self.email), "last_update": self.update_datetime}

    with app.app_context():
        db.create_all()

    def tear_down():
        if realdburl:
            db.drop_all()
            _teardown_realdb(db_info)

    request.addfinalizer(tear_down)

    return SQLAlchemyUserDatastore(db, User, Role)


@pytest.fixture()
def sqlalchemy_session_datastore(request, app, tmpdir, realdburl):
    return sqlalchemy_session_setup(request, app, tmpdir, realdburl)


def sqlalchemy_session_setup(request, app, tmpdir, realdburl):
    pytest.importorskip("sqlalchemy")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import scoped_session, sessionmaker, relationship, backref
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.sql import func
    from sqlalchemy import (
        Boolean,
        DateTime,
        Column,
        Integer,
        String,
        Text,
        ForeignKey,
        UnicodeText,
    )

    f, path = tempfile.mkstemp(
        prefix="flask-security-test-db", suffix=".db", dir=str(tmpdir)
    )

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + path

    engine = create_engine(app.config["SQLALCHEMY_DATABASE_URI"])
    db_session = scoped_session(
        sessionmaker(autocommit=False, autoflush=False, bind=engine)
    )
    Base = declarative_base()
    Base.query = db_session.query_property()

    class RolesUsers(Base):
        __tablename__ = "roles_users"
        id = Column(Integer(), primary_key=True)
        user_id = Column("user_id", Integer(), ForeignKey("user.myuserid"))
        role_id = Column("role_id", Integer(), ForeignKey("role.myroleid"))

    class Role(Base, RoleMixin):
        __tablename__ = "role"
        myroleid = Column(Integer(), primary_key=True)
        name = Column(String(80), unique=True)
        description = Column(String(255))
        permissions = Column(UnicodeText, nullable=True)
        update_datetime = Column(
            DateTime,
            nullable=False,
            server_default=func.now(),
            onupdate=datetime.utcnow,
        )

    class User(Base, UserMixin):
        __tablename__ = "user"
        myuserid = Column(Integer, primary_key=True)
        fs_uniquifier = Column(String(64), unique=True, nullable=False)
        email = Column(String(255), unique=True)
        username = Column(String(255), unique=True, nullable=True)
        password = Column(String(255))
        security_number = Column(Integer, unique=True)
        last_login_at = Column(DateTime())
        current_login_at = Column(DateTime())
        tf_primary_method = Column(String(255), nullable=True)
        tf_totp_secret = Column(String(255), nullable=True)
        tf_phone_number = Column(String(255), nullable=True)
        us_totp_secrets = Column(Text, nullable=True)
        us_phone_number = Column(String(64), nullable=True)
        last_login_ip = Column(String(100))
        current_login_ip = Column(String(100))
        login_count = Column(Integer)
        active = Column(Boolean())
        confirmed_at = Column(DateTime())
        roles = relationship(
            "Role", secondary="roles_users", backref=backref("users", lazy="dynamic")
        )
        update_datetime = Column(
            DateTime,
            nullable=False,
            server_default=func.now(),
            onupdate=datetime.utcnow,
        )

        def get_security_payload(self):
            # Make sure we still properly hook up to flask JSONEncoder
            return {"email": str(self.email), "last_update": self.update_datetime}

    with app.app_context():
        Base.metadata.create_all(bind=engine)

    def tear_down():
        db_session.close()
        os.close(f)
        os.remove(path)

    request.addfinalizer(tear_down)

    return SQLAlchemySessionUserDatastore(db_session, User, Role)


@pytest.fixture()
def peewee_datastore(request, app, tmpdir, realdburl):
    return peewee_setup(request, app, tmpdir, realdburl)


def peewee_setup(request, app, tmpdir, realdburl):
    pytest.importorskip("peewee")
    from peewee import (
        TextField,
        DateTimeField,
        IntegerField,
        BooleanField,
        ForeignKeyField,
        CharField,
    )
    from playhouse.flask_utils import FlaskDB

    if realdburl:
        engine_mapper = {
            "postgres": "peewee.PostgresqlDatabase",
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

    class Role(RoleMixin, db.Model):
        name = CharField(unique=True, max_length=80)
        description = TextField(null=True)
        permissions = TextField(null=True)

    class User(UserMixin, db.Model):
        email = TextField(unique=True, null=False)
        fs_uniquifier = TextField(unique=True, null=False)
        username = TextField(unique=True, null=True)
        security_number = IntegerField(null=True)
        password = TextField(null=True)
        last_login_at = DateTimeField(null=True)
        current_login_at = DateTimeField(null=True)
        tf_primary_method = TextField(null=True)
        tf_totp_secret = TextField(null=True)
        tf_phone_number = TextField(null=True)
        us_totp_secrets = TextField(null=True)
        us_phone_number = TextField(null=True)
        last_login_ip = TextField(null=True)
        current_login_ip = TextField(null=True)
        login_count = IntegerField(null=True)
        active = BooleanField(default=True)
        confirmed_at = DateTimeField(null=True)

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
        for Model in (Role, User, UserRoles):
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

    request.addfinalizer(tear_down)

    return PeeweeUserDatastore(db, User, Role, UserRoles)


@pytest.fixture()
def pony_datastore(request, app, tmpdir, realdburl):
    return pony_setup(request, app, tmpdir, realdburl)


def pony_setup(request, app, tmpdir, realdburl):

    pytest.importorskip("pony")
    from pony.orm import Database, Optional, Required, Set
    from pony.orm.core import SetInstance

    SetInstance.append = SetInstance.add
    db = Database()

    class Role(db.Entity):
        name = Required(str, unique=True)
        description = Optional(str, nullable=True)
        users = Set(lambda: User)

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
        db.bind(
            provider=pieces.scheme.split("+")[0],
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
        if realdburl:
            _teardown_realdb(db_info)

    request.addfinalizer(tear_down)

    return PonyUserDatastore(db, User, Role)


@pytest.fixture()
def sqlalchemy_app(app, sqlalchemy_datastore):
    def create():
        app.security = Security(app, datastore=sqlalchemy_datastore)
        return app

    return create


@pytest.fixture()
def sqlalchemy_session_app(app, sqlalchemy_session_datastore):
    def create():
        app.security = Security(app, datastore=sqlalchemy_session_datastore)
        return app

    return create


@pytest.fixture()
def peewee_app(app, peewee_datastore):
    def create():
        app.security = Security(app, datastore=peewee_datastore)
        return app

    return create


@pytest.fixture()
def mongoengine_app(app, mongoengine_datastore):
    def create():
        app.security = Security(app, datastore=mongoengine_datastore)
        return app

    return create


@pytest.fixture()
def pony_app(app, pony_datastore):
    def create():
        app.security = Security(app, datastore=pony_datastore)
        return app

    return create


@pytest.fixture()
def client(request, sqlalchemy_app):
    app = sqlalchemy_app()
    populate_data(app)
    return app.test_client()


@pytest.fixture()
def client_nc(request, sqlalchemy_app):
    # useful for testing token auth.
    # No Cookies for You!
    app = sqlalchemy_app()
    populate_data(app)
    return app.test_client(use_cookies=False)


@pytest.fixture(params=["cl-sqlalchemy", "c2", "cl-mongo", "cl-peewee"])
def clients(request, app, tmpdir, realdburl):
    if request.param == "cl-sqlalchemy":
        ds = sqlalchemy_setup(request, app, tmpdir, realdburl)
    elif request.param == "c2":
        ds = sqlalchemy_session_setup(request, app, tmpdir, realdburl)
    elif request.param == "cl-mongo":
        ds = mongoengine_setup(request, app, tmpdir, realdburl)
    elif request.param == "cl-peewee":
        ds = peewee_setup(request, app, tmpdir, realdburl)
    elif request.param == "cl-pony":
        # Not working yet.
        ds = pony_setup(request, app, tmpdir, realdburl)
    app.security = Security(app, datastore=ds)
    populate_data(app)
    if request.param == "cl-peewee":
        # peewee is insistent on a single connection?
        ds.db.close_db(None)
    return app.test_client()


@pytest.fixture()
def in_app_context(request, sqlalchemy_app):
    app = sqlalchemy_app()
    with app.app_context():
        yield app


@pytest.fixture()
def get_message(app):
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
    params=["sqlalchemy", "sqlalchemy-session", "mongoengine", "peewee", "pony"]
)
def datastore(request, app, tmpdir, realdburl):
    if request.param == "sqlalchemy":
        rv = sqlalchemy_setup(request, app, tmpdir, realdburl)
    elif request.param == "sqlalchemy-session":
        rv = sqlalchemy_session_setup(request, app, tmpdir, realdburl)
    elif request.param == "mongoengine":
        rv = mongoengine_setup(request, app, tmpdir, realdburl)
    elif request.param == "peewee":
        rv = peewee_setup(request, app, tmpdir, realdburl)
    elif request.param == "pony":
        rv = pony_setup(request, app, tmpdir, realdburl)
    return rv


@pytest.fixture()
# def script_info(app, datastore): # Fix me when pony works
def script_info(app, sqlalchemy_datastore):
    from flask.cli import ScriptInfo

    def create_app():
        uia = [
            {"email": {"mapper": uia_email_mapper}},
            {"username": {"mapper": lambda x: x}},
        ]

        app.config.update(**{"SECURITY_USER_IDENTITY_ATTRIBUTES": uia})
        app.security = Security(app, datastore=sqlalchemy_datastore)
        return app

    return ScriptInfo(create_app=create_app)


def pytest_addoption(parser):
    parser.addoption(
        "--realdburl",
        action="store",
        default=None,
        help="""Set url for using real database for testing.
        For postgres: 'postgres://user:password@host/')""",
    )


@pytest.fixture(scope="session")
def realdburl(request):
    """
    Support running datastore tests against a real DB.
    For example psycopg2 is very strict about types in queries
    compared to sqlite
    To use postgres you need to of course run a postgres instance on localhost
    then pass in an extra arg to pytest:
    --realdburl postgres://<user>@localhost/
    For mysql same - just download and add a root password.
    --realdburl "mysql+pymysql://root:<password>@localhost/"
    """
    return request.config.option.realdburl


def _setup_realdb(realdburl):
    """
    Called when we want to run unit tests against a real DB.
    This is useful since different DB drivers are pickier about queries etc
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
