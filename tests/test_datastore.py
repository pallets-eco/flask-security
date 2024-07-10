"""
    test_datastore
    ~~~~~~~~~~~~~~

    Datastore tests

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import pytest
from pytest import raises, skip, importorskip
from tests.test_utils import init_app_with_options, capture_queries

from flask_security import (
    RoleMixin,
    Security,
    UserMixin,
    LoginForm,
    RegisterForm,
    naive_utcnow,
)
from flask_security.datastore import Datastore, UserDatastore


class User(UserMixin):
    pass


class Role(RoleMixin):
    pass


class MockDatastore(UserDatastore):
    def put(self, model):
        pass

    def delete(self, model):
        pass


def test_unimplemented_datastore_methods():
    datastore = Datastore(None)
    assert datastore.db is None
    with raises(NotImplementedError):
        datastore.put(None)
    with raises(NotImplementedError):
        datastore.delete(None)
    assert not datastore.commit()


def test_unimplemented_user_datastore_methods():
    datastore = UserDatastore(None, None)
    with raises(NotImplementedError):
        datastore.find_user()
    with raises(NotImplementedError):
        datastore.find_role(None)


def test_toggle_active():
    datastore = MockDatastore(None, None)
    user = User()
    user.active = True
    assert datastore.toggle_active(user) is True
    assert not user.active
    assert datastore.toggle_active(user) is True
    assert user.active is True


def test_deactivate_user():
    datastore = MockDatastore(None, None)
    user = User()
    user.active = True
    assert datastore.deactivate_user(user) is True
    assert not user.active


def test_activate_user():
    datastore = MockDatastore(None, None)
    user = User()
    user.active = False
    assert datastore.activate_user(user) is True
    assert user.active is True


def test_deactivate_returns_false_if_already_false():
    datastore = UserDatastore(None, None)
    user = User()
    user.active = False
    assert not datastore.deactivate_user(user)


def test_activate_returns_false_if_already_true():
    datastore = UserDatastore(None, None)
    user = User()
    user.active = True
    assert not datastore.activate_user(user)


@pytest.mark.parametrize(
    "ds",
    ["sqlalchemy_datastore", "fsqlalite_datastore", "sqlalchemy_session_datastore"],
)
def test_find_user(request, app, ds):
    ds = request.getfixturevalue(ds)
    init_app_with_options(app, ds)

    with app.app_context():
        user_id = ds.find_user(email="gene@lp.com").fs_uniquifier

        with capture_queries(ds) as queries:
            assert user_id == ds.find_user(security_number=889900).fs_uniquifier
        assert len(queries) == 1
        assert queries[0].is_select

        assert user_id == ds.find_user(username="gene").fs_uniquifier


@pytest.mark.parametrize(
    "ds",
    ["sqlalchemy_datastore", "fsqlalite_datastore", "sqlalchemy_session_datastore"],
)
@pytest.mark.settings(join_user_roles=False)
def test_find_user_no_joined_load(request, app, ds):
    ds = request.getfixturevalue(ds)
    init_app_with_options(app, ds)

    with app.app_context():
        with capture_queries(ds) as queries:
            user = ds.find_user(security_number=889900)
            assert len(user.roles) == 1
        assert len(queries) == 2
        assert queries[0].is_select
        assert queries[0].statement.column_descriptions[0]["name"] == "User"
        assert queries[1].statement.column_descriptions[0]["name"] == "Role"


def test_find_role(app, datastore):
    init_app_with_options(app, datastore)

    with app.app_context():
        role = datastore.find_role("admin")
        assert role is not None

        role = datastore.find_role("bogus")
        assert role is None


def test_add_role_to_user(app, datastore):
    init_app_with_options(app, datastore)

    with app.app_context():
        # Test with user object
        user = datastore.find_user(email="matt@lp.com")
        assert user.has_role("editor") is False
        assert datastore.add_role_to_user(user, "editor") is True
        assert datastore.add_role_to_user(user, "editor") is False
        assert user.has_role("editor") is True

        # Test remove role
        assert datastore.remove_role_from_user(user, "editor") is True
        assert datastore.remove_role_from_user(user, "editor") is False


@pytest.mark.parametrize(
    "ds",
    ["sqlalchemy_datastore", "fsqlalite_datastore", "sqlalchemy_session_datastore"],
)
def test_create_user_with_roles(request, app, ds):
    ds = request.getfixturevalue(ds)
    init_app_with_options(app, ds)

    with app.app_context():
        role = ds.find_role("admin")
        user = ds.create_user(
            email="dude@lp.com", username="dude", password="password", roles=[role]
        )
        ds.commit()
        with capture_queries(ds) as queries:
            user = ds.find_user(email="dude@lp.com")
            assert user.has_role("admin") is True
        assert len(queries) == 1
        assert queries[0].is_select


def test_create_user_no_side_effects(app, datastore):
    init_app_with_options(app, datastore)

    with app.app_context():
        datastore.find_role("admin")
        roles = ["admin"]
        datastore.commit()

        datastore.create_user(
            email="dude@lp.com", username="dude", password="password", roles=roles
        )

        assert all(isinstance(role, str) for role in roles)


def test_delete_user(app, datastore):
    init_app_with_options(app, datastore)

    with app.app_context():
        user = datastore.find_user(email="matt@lp.com")
        datastore.delete_user(user)
        datastore.commit()
        user = datastore.find_user(email="matt@lp.com")
        assert user is None


def test_access_datastore_from_factory(app, datastore):
    security = Security()
    security.init_app(app, datastore)

    assert security.datastore is not None
    assert security.app is not None


def test_access_datastore_from_app_factory_pattern(app, datastore):
    security = Security(datastore=datastore)
    security.init_app(app)

    assert security.datastore is not None
    assert security.app is not None


def test_init_app_kwargs_override_constructor_kwargs(app, datastore):
    class ConLoginForm(LoginForm):
        pass

    class ConRegisterForm(RegisterForm):
        pass

    class InitLoginForm(LoginForm):
        pass

    security = Security(
        datastore=datastore,
        login_form=ConLoginForm,
        register_form=ConRegisterForm,
    )
    security.init_app(app, login_form=InitLoginForm)

    assert security.forms["login_form"].cls == InitLoginForm
    assert security.forms["register_form"].cls == ConRegisterForm


def test_create_user_with_roles_and_permissions(app, datastore):
    ds = datastore
    if not hasattr(ds.role_model, "permissions"):
        return
    init_app_with_options(app, datastore)

    with app.app_context():
        role = ds.create_role(name="test1", permissions={"read"})
        ds.commit()

        user = ds.create_user(
            email="dude@lp.com", username="dude", password="password", roles=[role]
        )
        datastore.commit()

        user = datastore.find_user(email="dude@lp.com")
        assert user.has_role("test1") is True
        assert user.has_permission("read") is True
        assert user.has_permission("write") is False


def test_permissions_types(app, datastore):
    # Test permissions as a list, set, tuple, comma separated list
    ds = datastore
    if not hasattr(ds.role_model, "permissions"):
        return
    init_app_with_options(app, ds)

    with app.app_context():
        perms = ["read", "write"]
        ds.create_role(name="test1", permissions=perms)
        ds.commit()

        t1 = ds.find_role("test1")
        assert {"read", "write"} == t1.get_permissions()

        perms = {"read", "write"}
        ds.create_role(name="test2", permissions=perms)
        ds.commit()

        t2 = ds.find_role("test2")
        assert {"read", "write"} == t2.get_permissions()

        perms = "read, write"
        ds.create_role(name="test3", permissions=perms)
        ds.commit()

        t3 = ds.find_role("test3")
        assert {"read", "write"} == t3.get_permissions()

        perms = ("read", "write")
        ds.create_role(name="test4", permissions=perms)
        ds.commit()

        t4 = ds.find_role("test4")
        assert {"read", "write"} == t4.get_permissions()

        ds.create_role(
            name="test5",
            permissions={"read"},
        )
        ds.commit()

        t5 = ds.find_role("test5")
        assert {"read"} == t5.get_permissions()


def test_modify_permissions(app, datastore):
    ds = datastore
    if not hasattr(ds.role_model, "permissions"):
        return
    init_app_with_options(app, ds)

    with app.app_context():
        perms = {"read", "write"}
        ds.create_role(name="test1", permissions=perms)
        ds.commit()

        t1 = ds.find_role("test1")
        assert perms == t1.get_permissions()
        if hasattr(t1, "update_datetime"):
            orig_update_time = t1.update_datetime
            assert t1.update_datetime <= naive_utcnow()

        ds.add_permissions_to_role(t1, "execute")
        ds.commit()

        t1 = ds.find_role("test1")
        assert perms.union({"execute"}) == t1.get_permissions()

        ds.remove_permissions_from_role(t1, "read")
        ds.commit()
        t1 = ds.find_role("test1")
        assert {"write", "execute"} == t1.get_permissions()
        if hasattr(t1, "update_datetime"):
            assert t1.update_datetime > orig_update_time


def test_get_permissions(app, datastore):
    """Verify that role.permissions = None works."""
    ds = datastore
    if not hasattr(ds.role_model, "permissions"):
        return
    init_app_with_options(app, ds)

    with app.app_context():
        t1 = ds.find_role("simple")
        assert set() == t1.get_permissions()


def test_modify_permissions_multi(app, datastore):
    ds = datastore
    if not hasattr(ds.role_model, "permissions"):
        return

    init_app_with_options(app, ds)

    with app.app_context():
        perms = ["read", "write"]
        ds.create_role(name="test1", permissions=perms)
        ds.commit()

        t1 = ds.find_role("test1")
        assert {"read", "write"} == t1.get_permissions()

        # send in a list
        ds.add_permissions_to_role(t1, ["execute", "whatever"])
        ds.commit()

        t1 = ds.find_role("test1")
        assert {"read", "write", "execute", "whatever"} == t1.get_permissions()

        ds.remove_permissions_from_role(t1, ["read", "whatever"])
        ds.commit()
        assert {"write", "execute"} == t1.get_permissions()

        # send in a set
        perms = {"read", "write"}
        ds.create_role(name="test2", permissions=perms)
        ds.commit()

        # add permissions using comma separate string
        t2 = ds.find_role("test2")
        ds.add_permissions_to_role(t2, "execute, whatever")
        ds.commit()

        t2 = ds.find_role("test2")
        assert {"read", "write", "execute", "whatever"} == t2.get_permissions()

        ds.remove_permissions_from_role(t2, {"read", "whatever"})
        ds.commit()
        assert {"write", "execute"} == t2.get_permissions()

        ds.remove_permissions_from_role(t2, "write, execute")
        ds.commit()
        assert t2.get_permissions() == set()

        # add permissions using a tuple
        t2 = ds.find_role("test2")
        ds.add_permissions_to_role(t2, ("execute2", "whatever2"))
        ds.commit()
        assert {"whatever2", "execute2"} == t2.get_permissions()


def test_uuid(app, request, tmpdir, realdburl):
    """Test that UUID extension of postgresql works as a primary id for users"""
    importorskip("flask_sqlalchemy")
    import uuid
    from flask_sqlalchemy import SQLAlchemy
    from sqlalchemy import Boolean, Column, DateTime, Integer, ForeignKey, String
    from sqlalchemy.dialects.postgresql import UUID
    from sqlalchemy.orm import relationship, backref

    from flask_security import SQLAlchemyUserDatastore
    from tests.conftest import _setup_realdb, _teardown_realdb

    # UUID type only supported by postgres - not sqlite.
    if not realdburl or "postgresql" not in realdburl:
        skip("This test only works on postgres")
    db_url, db_info = _setup_realdb(realdburl)
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url

    db = SQLAlchemy(app)

    class RolesUsers(db.Model):
        __tablename__ = "roles_users"
        id = Column(Integer(), primary_key=True)
        user_id = Column("user_id", UUID(as_uuid=True), ForeignKey("user.id"))
        role_id = Column("role_id", UUID(as_uuid=True), ForeignKey("role.id"))

    class User(db.Model, UserMixin):
        __tablename__ = "user"
        id = Column(
            UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True
        )
        email = Column(String(255), unique=True)
        fs_uniquifier = Column(String(64), unique=True, nullable=False)
        first_name = Column(String(255), index=True)
        last_name = Column(String(255), index=True)
        username = Column(String(255), unique=True, nullable=True)
        password = Column(String(255))
        active = Column(Boolean())
        created_at = Column(DateTime, default=naive_utcnow())
        confirmed_at = Column(DateTime())
        roles = relationship(
            "Role", secondary="roles_users", backref=backref("users", lazy="dynamic")
        )

    class Role(db.Model, RoleMixin):
        __tablename__ = "role"
        id = Column(
            UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True
        )
        name = Column(String(80), unique=True)
        description = Column(String(255))

        # __hash__ is required to avoid the exception
        # TypeError: unhashable type: 'Role' when saving a User
        def __hash__(self):
            return hash(self.name)

    with app.app_context():
        db.create_all()

    def tear_down():
        with app.app_context():
            db.drop_all()
            _teardown_realdb(db_info)

    request.addfinalizer(tear_down)

    ds = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(app, datastore=ds)

    with app.app_context():
        user = ds.find_user(email="matt@lp.com")
        assert not user


def test_webauthn(app, datastore):
    importorskip("webauthn")
    if not datastore.webauthn_model:
        skip("No WebAuthn model defined")
    init_app_with_options(app, datastore)

    with app.app_context():
        user = datastore.find_user(email="matt@lp.com")
        datastore.create_webauthn(
            user,
            name="cred1",
            credential_id=b"1",
            public_key=b"key",
            sign_count=0,
            transports=None,
            extensions=None,
            usage="first",
            device_type="single_device",
            backup_state=False,
        )
        datastore.commit()
        cred = datastore.find_webauthn(b"1")
        assert cred.name == "cred1"

        user = datastore.find_user(email="matt@lp.com")
        assert len(user.webauthn) == 1
        assert user.webauthn[0].name == "cred1"

        datastore.delete_webauthn(user.webauthn[0])
        datastore.commit()
        user = datastore.find_user(email="matt@lp.com")
        assert len(user.webauthn) == 0


def test_webauthn_cascade(app, datastore):
    importorskip("webauthn")
    if not datastore.webauthn_model:
        skip("No WebAuthn model defined")
    init_app_with_options(app, datastore)

    with app.app_context():
        user = datastore.find_user(email="matt@lp.com")
        datastore.create_webauthn(
            user,
            name="cred1",
            credential_id=b"1",
            public_key=b"key",
            sign_count=0,
            transports=None,
            extensions=None,
            usage="first",
            device_type="single_device",
            backup_state=False,
        )
        datastore.create_webauthn(
            user,
            name="cred2",
            credential_id=b"2",
            public_key=b"key",
            sign_count=0,
            transports=None,
            extensions=None,
            usage="secondary",
            device_type="single_device",
            backup_state=False,
        )
        datastore.commit()

        user = datastore.find_user(email="matt@lp.com")
        assert len(user.webauthn) == 2
        names = [cred.name for cred in user.webauthn]
        assert set(names) == {"cred1", "cred2"}
        assert datastore.find_webauthn(b"1")

        # delete user
        datastore.delete_user(user)
        datastore.commit()
        user = datastore.find_user(email="matt@lp.com")
        assert not user

        cred = datastore.find_webauthn(b"1")
        assert not cred
        cred = datastore.find_webauthn(b"2")
        assert not cred


def test_mf_recovery_codes(app, datastore):
    from tests.conftest import PonyUserDatastore

    if isinstance(datastore, PonyUserDatastore):
        skip("Pony not supported")
    init_app_with_options(app, datastore)

    with app.test_request_context("/"):
        user = datastore.find_user(email="matt@lp.com")
        assert hasattr(user, "mf_recovery_codes")

        assert not datastore.mf_delete_recovery_code(user, 0)

        datastore.mf_set_recovery_codes(user, ["r1", "r2", "r3"])
        datastore.commit()

        user = datastore.find_user(email="matt@lp.com")
        codes = datastore.mf_get_recovery_codes(user)
        assert codes == ["r1", "r2", "r3"]

        rv = datastore.mf_delete_recovery_code(user, 1)
        assert rv
        datastore.commit()

        rv = datastore.mf_delete_recovery_code(user, 4)
        assert not rv

        user = datastore.find_user(email="matt@lp.com")
        codes = datastore.mf_get_recovery_codes(user)
        assert codes == ["r1", "r3"]


def test_permissions_fsqla_v2(app):
    importorskip("sqlalchemy")
    importorskip("flask_sqlalchemy")
    # Make sure folks with fsqla_v2 work with new AsList column type
    from sqlalchemy import insert
    from flask_sqlalchemy import SQLAlchemy
    from flask_security.models import fsqla_v2 as fsqla
    from flask_security import Security
    from flask_security import SQLAlchemyUserDatastore

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    db = SQLAlchemy(app)

    fsqla.FsModels.set_db_info(db)

    class Role(db.Model, fsqla.FsRoleMixin):
        pass

    class User(db.Model, fsqla.FsUserMixin):
        pass

    with app.app_context():
        db.create_all()
        meta_data = db.MetaData()
        meta_data.reflect(db.engine)
        role_table = meta_data.tables["role"]

        # Start by manually creating a role in the 4.1.x style
        stmt = insert(role_table).values(
            name="r1", description="r1 v41", permissions="read,write"
        )
        with db.engine.connect() as conn:
            with conn.begin():
                conn.execute(stmt)

    ds = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(app, datastore=ds)

    with app.app_context():
        # Verify can read something written by 4.x
        r1 = ds.find_role("r1")
        assert r1.get_permissions() == {"read", "write"}

        ds.create_role(name="test5", permissions={"read"})
        ds.commit()

        t5 = ds.find_role("test5")
        assert {"read"} == t5.get_permissions()


def test_permissions_41(request, app, realdburl):
    importorskip("sqlalchemy")
    importorskip("flask_sqlalchemy")
    # Check compatibility with 4.1 DB
    from sqlalchemy import Column, insert
    from flask_sqlalchemy import SQLAlchemy
    from flask_security.models import fsqla_v2 as fsqla
    from flask_security import Security
    from flask_security import SQLAlchemyUserDatastore
    from tests.conftest import _setup_realdb, _teardown_realdb

    if realdburl:
        db_url, db_info = _setup_realdb(realdburl)
        app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

    def tear_down():
        if realdburl:
            with app.app_context():
                db.drop_all()
                _teardown_realdb(db_info)

    request.addfinalizer(tear_down)

    db = SQLAlchemy(app)
    fsqla.FsModels.set_db_info(db)

    class Role(db.Model, fsqla.FsRoleMixin):
        # permissions = Column(UnicodeText, nullable=True)  # type: ignore
        from flask_security import AsaList
        from sqlalchemy.ext.mutable import MutableList

        # A comma separated list of strings
        permissions = Column(
            MutableList.as_mutable(AsaList()), nullable=True  # type: ignore
        )

    class User(db.Model, fsqla.FsUserMixin):
        pass

    with app.app_context():
        db.create_all()
        meta_data = db.MetaData()
        meta_data.reflect(db.engine)
        role_table = meta_data.tables["role"]

        # Start by manually creating a role in the 4.1.x style
        stmt = insert(role_table).values(
            name="r1", description="r1 v41", permissions="read,write"
        )
        with db.engine.connect() as conn:
            with conn.begin():
                conn.execute(stmt)

    ds = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(app, datastore=ds)

    with app.app_context():
        r1 = ds.find_role("r1")
        assert r1.get_permissions() == {"read", "write"}


def test_fsqlalite_table_name(app):
    importorskip("flask_sqlalchemy_lite")
    from flask_sqlalchemy_lite import SQLAlchemy
    from sqlalchemy.orm import DeclarativeBase
    from flask_security.models import sqla as sqla
    from flask_security import FSQLALiteUserDatastore

    app.config |= {
        "SQLALCHEMY_ENGINES": {
            "default": "sqlite:///:memory:",
        },
    }
    db = SQLAlchemy(app)

    class Model(DeclarativeBase):
        pass

    sqla.FsModels.set_db_info(
        base_model=Model,
        user_table_name="myuser",
        role_table_name="myrole",
        webauthn_table_name="mywebauthn",
    )

    class Role(Model, sqla.FsRoleMixin):
        __tablename__ = "myrole"

    class WebAuthn(Model, sqla.FsWebAuthnMixin):
        __tablename__ = "mywebauthn"

    class User(Model, sqla.FsUserMixin):
        __tablename__ = "myuser"

    with app.app_context():
        Model.metadata.create_all(db.engine)

    ds = FSQLALiteUserDatastore(db, User, Role, WebAuthn)
    app.security = Security(app, datastore=ds)

    with app.app_context():
        ds.create_role(name="r1")
        ds.create_user(email="me@lp.com", roles=["r1"])
        ds.commit()
        user = ds.find_user(email="me@lp.com")
        assert user
        Model.metadata.drop_all(db.engine)
