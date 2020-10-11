"""
Copyright 2019-2020 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.


Complete models for all features when using Flask-SqlAlchemy.

You can change the table names by passing them in to the set_db_info() method.

BE AWARE: Once any version of this is shipped no changes can be made - instead
a new version needs to be created.
"""

import datetime
from sqlalchemy import (
    Boolean,
    DateTime,
    Column,
    Integer,
    String,
    UnicodeText,
    ForeignKey,
)
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from flask_security import RoleMixin, UserMixin


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

    @classmethod
    def set_db_info(cls, appdb, user_table_name="user", role_table_name="role"):
        """Initialize Model.
        This needs to be called after the DB object has been created
        (e.g. db = Sqlalchemy())
        """
        cls.db = appdb
        cls.user_table_name = user_table_name
        cls.role_table_name = role_table_name
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
    permissions = Column(UnicodeText, nullable=True)
    update_datetime = Column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=datetime.datetime.utcnow,
    )


class FsUserMixin(UserMixin):
    """User information"""

    # flask_security basic fields
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    # Username is important since shouldn't expose email to other users in most cases.
    username = Column(String(255))
    password = Column(String(255), nullable=False)
    active = Column(Boolean(), nullable=False)

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
            backref=FsModels.db.backref("users", lazy="dynamic"),
        )

    create_datetime = Column(DateTime, nullable=False, server_default=func.now())
    update_datetime = Column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=datetime.datetime.utcnow,
    )


"""
These are placeholders - not current used
"""


class FsOauth2ClientMixin:
    """ Oauth2 client """

    id = Column(String(64), primary_key=True)

    @declared_attr
    def user_id(cls):
        return Column(
            Integer, ForeignKey("user.id", ondelete="CASCADE"), nullable=False
        )

    @declared_attr
    def user(cls):
        return relationship("User")

    grant_type = Column(String(32), nullable=False)
    scopes = Column(UnicodeText(), default="")
    response_type = Column(UnicodeText, nullable=False, default="")
    redirect_uris = Column(UnicodeText())


class FsTokenMixin:
    """ (Bearer) Tokens that have been given out """

    id = Column(Integer, primary_key=True)

    @declared_attr
    def client_id(cls):
        return Column(
            Integer, ForeignKey("oauth2_client.id", ondelete="CASCADE"), nullable=False
        )

    # client = relationship("fs_oauth2_client")
    @declared_attr
    def user_id(cls):
        return Column(
            Integer, ForeignKey("user.id", ondelete="CASCADE"), nullable=False
        )

    scopes = Column(UnicodeText(), default="")
    revoked = Column(Boolean(), nullable=False, default=False)
    access_token = Column(String(100), unique=True, nullable=False)
    refresh_token = Column(String(100), unique=True)
    issued_at = Column(DateTime, nullable=False, server_default=func.now())
    expires_at = Column(DateTime())
