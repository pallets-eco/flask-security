"""
Copyright 2019-2024 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.


Complete models for all features when using Flask-SqlAlchemy.

You can change the table names by passing them in to the set_db_info() method.

BE AWARE: Once any version of this is shipped no changes can be made - instead
a new version needs to be created.
"""

from typing import cast
from sqlalchemy import (
    Boolean,
    DateTime,
    Column,
    Integer,
    String,
    ForeignKey,
)
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.sql import func

from flask_security import AsaList, RoleMixin, UserMixin, naive_utcnow


class FsModels:
    """
    Helper class for model mixins.
    This records the ``db`` (which is a Flask-SqlAlchemy object) for use in
    mixins.
    """

    roles_users = None
    db = None
    fs_model_version = 1
    user_table_name = "user"
    role_table_name = "role"
    webauthn_table_name = "webauthn"

    @classmethod
    def set_db_info(
        cls,
        appdb,
        user_table_name="user",
        role_table_name="role",
        webauthn_table_name="webauthn",
    ):
        """Initialize Model.
        This needs to be called after the DB object has been created
        (e.g. db = Sqlalchemy()).

        .. note::
            This should only be used if you are utilizing the fsqla data
            models. With your own models you would need similar but slightly
            difficult code.
        """
        cls.db = appdb
        cls.user_table_name = user_table_name
        cls.role_table_name = role_table_name
        cls.webauthn_table_name = webauthn_table_name
        cls.roles_users = appdb.Table(
            "roles_users",
            Column("user_id", Integer(), ForeignKey(f"{cls.user_table_name}.id")),
            Column("role_id", Integer(), ForeignKey(f"{cls.role_table_name}.id")),
        )


class FsRoleMixin(RoleMixin):
    id = Column(Integer(), primary_key=True)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(255))
    # A comma separated list of strings
    permissions = Column(
        MutableList.as_mutable(AsaList()), nullable=True  # type: ignore
    )
    update_datetime = Column(
        type_=DateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=naive_utcnow,
    )


class FsUserMixin(UserMixin):
    """User information"""

    # flask_security basic fields
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    # Username is important since shouldn't expose email to other users in most cases.
    username = Column(String(255))
    password = Column(String(255), nullable=False)
    active = cast(bool, Column(Boolean(), nullable=False))

    # Flask-Security user identifier
    fs_uniquifier = Column(String(64), unique=True, nullable=False)

    # confirmable
    confirmed_at = Column(DateTime())

    # trackable
    last_login_at = Column(DateTime())
    current_login_at = Column(DateTime())
    last_login_ip = Column(String(64))
    current_login_ip = Column(String(64))
    login_count = Column(Integer)

    # 2FA
    tf_primary_method = Column(String(64), nullable=True)
    tf_totp_secret = Column(String(255), nullable=True)
    tf_phone_number = Column(String(128), nullable=True)

    @declared_attr
    def roles(cls):
        # The first arg is a class name, the backref is a column name
        return FsModels.db.relationship(
            "Role",
            secondary=FsModels.roles_users,
            backref=FsModels.db.backref(
                "users", lazy="dynamic", cascade_backrefs=False
            ),
        )

    create_datetime = Column(type_=DateTime, nullable=False, server_default=func.now())
    update_datetime = Column(
        type_=DateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=naive_utcnow,
    )
