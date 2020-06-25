"""
    test_datastore
    ~~~~~~~~~~~~~~

    Datastore tests

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import datetime
from pytest import raises, skip
from tests.test_utils import init_app_with_options, get_num_queries, is_sqlalchemy

from flask_security import RoleMixin, Security, UserMixin
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
        datastore.find_user(None)
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


def test_find_user(app, datastore):
    init_app_with_options(app, datastore)

    with app.app_context():
        user_id = datastore.find_user(email="gene@lp.com").fs_uniquifier

        current_nqueries = get_num_queries(datastore)
        assert user_id == datastore.find_user(security_number=889900).fs_uniquifier
        end_nqueries = get_num_queries(datastore)
        if current_nqueries is not None:
            if is_sqlalchemy(datastore):
                # This should have done just 1 query across all attrs.
                assert end_nqueries == (current_nqueries + 1)

        assert user_id == datastore.find_user(username="gene").fs_uniquifier


def test_find_user_multikey(app, datastore):
    init_app_with_options(app, datastore)

    with app.app_context():
        with raises(ValueError):
            datastore.find_user(
                case_insensitive=True, email="gene@lp.com", security_number=889900
            )


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


def test_create_user_with_roles(app, datastore):
    init_app_with_options(app, datastore)

    with app.app_context():
        role = datastore.find_role("admin")
        datastore.commit()

        user = datastore.create_user(
            email="dude@lp.com", username="dude", password="password", roles=[role]
        )
        datastore.commit()
        current_nqueries = get_num_queries(datastore)
        user = datastore.find_user(email="dude@lp.com")
        assert user.has_role("admin") is True
        end_nqueries = get_num_queries(datastore)
        # Verify that getting user and role is just one DB query
        assert current_nqueries is None or end_nqueries == (current_nqueries + 1)


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
    security = Security(
        datastore=datastore,
        login_form="__init__login_form",
        register_form="__init__register_form",
    )
    security.init_app(app, login_form="init_app_login_form")

    assert security.login_form == "init_app_login_form"
    assert security.register_form == "__init__register_form"


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


def test_permissions_strings(app, datastore):
    # Make sure spaces are squashed.
    ds = datastore
    if not hasattr(ds.role_model, "permissions"):
        return
    init_app_with_options(app, ds)

    with app.app_context():
        perms = "read, write "
        ds.create_role(name="test1", permissions=perms)
        ds.commit()

        t1 = ds.find_role("test1")
        assert {"read", "write"} == t1.get_permissions()


def test_permissions_iter(app, datastore):
    # Test permissions as an interable
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
            assert t1.update_datetime <= datetime.datetime.utcnow()

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
    """ Verify that role.permissions = None works. """
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

    # N.B. right now only sqlalchemy has the extended RoleModel.
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
        ds.create_role(name="test2", permissions=",".join(perms))
        ds.commit()

        t2 = ds.find_role("test2")
        ds.add_permissions_to_role(t2, {"execute", "whatever"})
        ds.commit()

        t2 = ds.find_role("test2")
        assert {"read", "write", "execute", "whatever"} == t2.get_permissions()

        ds.remove_permissions_from_role(t2, {"read", "whatever"})
        ds.commit()
        assert {"write", "execute"} == t2.get_permissions()


def test_modify_permissions_unsupported(app, datastore):
    from tests.conftest import PonyUserDatastore

    ds = datastore
    if hasattr(datastore.role_model, "permissions"):
        # already tested this
        return
    if isinstance(datastore, PonyUserDatastore):
        # sigh - Pony doesn't use RoleMixin.
        return

    init_app_with_options(app, ds)

    with app.app_context():
        ds.create_role(name="test3")
        ds.commit()
        t3 = ds.find_role("test3")

        with raises(NotImplementedError):
            t3.add_permissions("whatever")
        with raises(NotImplementedError):
            t3.remove_permissions("whatever")


def test_uuid(app, request, tmpdir, realdburl):
    """ Test that UUID extension of postgresql works as a primary id for users """
    import uuid
    from flask_sqlalchemy import SQLAlchemy
    from sqlalchemy import Boolean, Column, DateTime, Integer, ForeignKey, String
    from sqlalchemy.dialects.postgresql import UUID
    from sqlalchemy.orm import relationship, backref

    from flask_security import SQLAlchemyUserDatastore
    from tests.conftest import _setup_realdb, _teardown_realdb

    # UUID type only supported by postgres - not sqlite.
    if not realdburl or "postgres" not in realdburl:
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
        created_at = Column(DateTime, default=datetime.datetime.utcnow)
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
        db.drop_all()
        _teardown_realdb(db_info)

    request.addfinalizer(tear_down)

    ds = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(app, datastore=ds)

    with app.app_context():
        user = ds.find_user(email="matt@lp.com")
        assert not user
