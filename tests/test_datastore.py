# -*- coding: utf-8 -*-
"""
    test_datastore
    ~~~~~~~~~~~~~~

    Datastore tests
"""

import datetime
from pytest import raises
from utils import init_app_with_options, get_num_queries, is_sqlalchemy

from flask_security import RoleMixin, Security, UserMixin
from flask_security.datastore import Datastore, UserDatastore


class User(UserMixin):
    pass


class Role(RoleMixin):
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
    with raises(NotImplementedError):
        datastore.get_user(None)


def test_toggle_active():
    datastore = UserDatastore(None, None)
    user = User()
    user.active = True
    assert datastore.toggle_active(user) is True
    assert not user.active
    assert datastore.toggle_active(user) is True
    assert user.active is True


def test_deactivate_user():
    datastore = UserDatastore(None, None)
    user = User()
    user.active = True
    assert datastore.deactivate_user(user) is True
    assert not user.active


def test_activate_user():
    datastore = UserDatastore(None, None)
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


def test_get_user(app, datastore):
    # The order of identity attributes is important for testing.
    # drivers like psycopg2 will abort the transaction if they throw an
    # error and not continue on so we want to check that case of passing in
    # a string for a numeric field and being able to move onto the next
    # column.
    init_app_with_options(
        app,
        datastore,
        **{
            "SECURITY_USER_IDENTITY_ATTRIBUTES": (
                "email",
                "security_number",
                "username",
            )
        }
    )

    with app.app_context():
        user_id = datastore.find_user(email="matt@lp.com").id

        user = datastore.get_user(user_id)
        assert user is not None

        user = datastore.get_user("matt@lp.com")
        assert user is not None

        user = datastore.get_user("matt")
        assert user is not None

        # Regression check (make sure we don't match wildcards)
        user = datastore.get_user("%lp.com")
        assert user is None

        # Verify that numeric non PK works
        user = datastore.get_user(123456)
        assert user is not None


def test_find_user(app, datastore):
    init_app_with_options(app, datastore)

    with app.app_context():
        user_id = datastore.find_user(email="gene@lp.com").id

        current_nqueries = get_num_queries(datastore)
        assert user_id == datastore.find_user(security_number=889900).id
        end_nqueries = get_num_queries(datastore)
        if current_nqueries is not None:
            if is_sqlalchemy(datastore):
                # This should have done just 1 query across all attrs.
                assert end_nqueries == (current_nqueries + 1)

        assert user_id == datastore.find_user(username="gene").id


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

        # Test with email
        assert datastore.add_role_to_user("jill@lp.com", "editor") is True
        user = datastore.find_user(email="jill@lp.com")
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
        orig_update_time = t1.update_datetime
        assert t1.update_datetime <= datetime.datetime.utcnow()

        t1.add_permissions("execute")
        ds.commit()

        t1 = ds.find_role("test1")
        assert perms.union({"execute"}) == t1.get_permissions()

        t1.remove_permissions("read")
        ds.commit()
        t1 = ds.find_role("test1")
        assert {"write", "execute"} == t1.get_permissions()
        assert t1.update_datetime > orig_update_time


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
        t1.add_permissions(["execute", "whatever"])
        ds.commit()

        t1 = ds.find_role("test1")
        assert {"read", "write", "execute", "whatever"} == t1.get_permissions()

        t1.remove_permissions(["read", "whatever"])
        ds.commit()
        assert {"write", "execute"} == t1.get_permissions()

        # send in a set
        perms = {"read", "write"}
        ds.create_role(name="test2", permissions=",".join(perms))
        ds.commit()

        t2 = ds.find_role("test2")
        t2.add_permissions({"execute", "whatever"})
        ds.commit()

        t2 = ds.find_role("test2")
        assert {"read", "write", "execute", "whatever"} == t2.get_permissions()

        t2.remove_permissions({"read", "whatever"})
        ds.commit()
        assert {"write", "execute"} == t2.get_permissions()


def test_modify_permissions_unsupported(app, datastore):
    from conftest import PonyUserDatastore

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
