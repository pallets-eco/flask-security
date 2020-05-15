"""
    test_entities
    ~~~~~~~~~~~~~

    Entity tests
"""
import inspect

from sqlalchemy import Column
from flask_security import AnonymousUser, RoleMixin, UserMixin
from flask_security.models import fsqla, fsqla_v2


class Role(RoleMixin):
    def __init__(self, name):
        self.name = name


class User(UserMixin):
    def __init__(self, roles):
        self.roles = roles


def test_role_mixin_equal():
    admin1 = Role("admin")
    admin2 = Role("admin")
    assert admin1 == admin2


def test_role_mixin_not_equal():
    admin = Role("admin")
    editor = Role("editor")
    assert admin != editor


def test_user_mixin_has_role_with_string():
    admin = Role("admin")
    editor = Role("editor")
    user = User([admin, editor])
    assert user.has_role("admin") is True
    assert user.has_role("editor") is True
    assert user.has_role(admin) is True
    assert user.has_role(editor) is True


def test_anonymous_user_has_no_roles():
    user = AnonymousUser()
    assert not user.has_role("admin")


def get_user_attributes(cls):
    boring = dir(type("dummy", (object,), {}))
    return [item for item in inspect.getmembers(cls) if item[0] not in boring]


def test_fsqla_fields():
    # basic test to verify no one modified fsqla after shipping.
    # Not perfect since not checking relationships etc.
    v1_user_attrs = {
        "id",
        "email",
        "password",
        "username",
        "active",
        "create_datetime",
        "update_datetime",
        "fs_uniquifier",
        "confirmed_at",
        "current_login_at",
        "current_login_ip",
        "last_login_at",
        "last_login_ip",
        "login_count",
        "tf_phone_number",
        "tf_primary_method",
        "tf_totp_secret",
    }
    attrs = {
        a[0] for a in get_user_attributes(fsqla.FsUserMixin) if isinstance(a[1], Column)
    }
    assert attrs == v1_user_attrs

    v2_user_attrs = {"us_totp_secrets", "us_phone_number"}
    attrs = {
        a[0]
        for a in get_user_attributes(fsqla_v2.FsUserMixin)
        if isinstance(a[1], Column)
    }
    assert attrs == v1_user_attrs.union(v2_user_attrs)

    v1_role_attrs = {"id", "name", "description", "permissions", "update_datetime"}
    attrs = {
        a[0] for a in get_user_attributes(fsqla.FsRoleMixin) if isinstance(a[1], Column)
    }
    assert attrs == v1_role_attrs

    attrs = {
        a[0]
        for a in get_user_attributes(fsqla_v2.FsRoleMixin)
        if isinstance(a[1], Column)
    }
    assert attrs == v1_role_attrs
