"""
Copyright 2024-2024 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.


Complete models for all features when using SqlAlchemy.
These are pure sqlalchemy declarative models - so should work with Flask-SQLAlchemy-Lite
as well as just sqlalchemy (such as using a scoped session).

You can change the table names by passing them in to the set_db_info() method.

BE AWARE: Once any version of this is shipped no changes can be made - instead
a new version needs to be created.
"""

# mypy: disable-error-code="assignment"
# pyright: reportAssignmentType = false, reportIncompatibleVariableOverride=false

from __future__ import annotations

import datetime

from sqlalchemy import (
    Column,
    LargeBinary,
    String,
    Table,
    Text,
    ForeignKey,
)
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.sql import func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from flask_security import AsaList, RoleMixin, UserMixin, WebAuthnMixin, naive_utcnow


class FsModels:
    """
    Helper class for model mixins.
    """

    roles_users = None
    fs_model_version = 1
    base_model: DeclarativeBase
    user_table_name = "user"
    role_table_name = "role"
    webauthn_table_name = "webauthn"

    @classmethod
    def set_db_info(
        cls,
        *,
        base_model,
        user_table_name="user",
        role_table_name="role",
        webauthn_table_name="webauthn",
    ):
        """Initialize Model.
        This MUST be called PRIOR to declaring your User/Role/WebAuthn model in order
        for table name altering to work.

        .. note::
            This should only be used if you are utilizing the sqla data
            models. With your own models you would need similar but slightly
            different code.
        """
        cls.base_model = base_model
        cls.user_table_name = user_table_name
        cls.role_table_name = role_table_name
        cls.webauthn_table_name = webauthn_table_name
        cls.roles_users = Table(
            "roles_users",
            cls.base_model.metadata,
            Column(
                "user_id", ForeignKey(f"{cls.user_table_name}.id"), primary_key=True
            ),
            Column(
                "role_id", ForeignKey(f"{cls.role_table_name}.id"), primary_key=True
            ),
        )


class FsRoleMixin(RoleMixin):
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    description: Mapped[str | None] = mapped_column(String(255))
    # A comma separated list of strings
    permissions: Mapped[list[str] | None] = mapped_column(  # type: ignore[assignment]
        MutableList.as_mutable(AsaList()),
    )
    update_datetime: Mapped[datetime.datetime] = mapped_column(
        server_default=func.now(),
        onupdate=naive_utcnow,
    )

    @declared_attr
    def users(cls):
        return relationship(
            "User",
            secondary="roles_users",
            back_populates="roles",
        )


class FsUserMixin(UserMixin):
    """User information"""

    # flask_security basic fields
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    # Make username unique but not required.
    username: Mapped[str | None] = mapped_column(String(255), unique=True)
    # Change password to nullable so we can tell after registration whether
    # a user has a password or not.
    password: Mapped[str | None] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column()

    # Flask-Security user identifier
    fs_uniquifier: Mapped[str] = mapped_column(String(64), unique=True)

    # confirmable
    confirmed_at: Mapped[datetime.datetime | None] = mapped_column()

    # trackable
    last_login_at: Mapped[datetime.datetime | None] = mapped_column()
    current_login_at: Mapped[datetime.datetime | None] = mapped_column()
    last_login_ip: Mapped[str | None] = mapped_column(String(64))
    current_login_ip: Mapped[str | None] = mapped_column(String(64))
    login_count: Mapped[int | None] = mapped_column()

    # 2FA
    tf_primary_method: Mapped[str | None] = mapped_column(String(64))
    tf_totp_secret: Mapped[str | None] = mapped_column(String(255))
    tf_phone_number: Mapped[str | None] = mapped_column(String(128))

    # unified sign in
    us_totp_secrets: Mapped[str | None] = mapped_column(Text)
    # since phone can be used to authenticate - must be unique.
    us_phone_number: Mapped[str | None] = mapped_column(String(128), unique=True)

    try:
        import webauthn as webauthn_pkg

        # List of WebAuthn registrations
        @declared_attr
        def webauthn(cls):
            return relationship(
                "WebAuthn", back_populates="user", cascade="all, delete"
            )

    except ImportError:  # pragma: no cover
        pass

    # The user handle as required during registration.
    # Note max length 64 as specified in spec.
    fs_webauthn_user_handle: Mapped[str | None] = mapped_column(String(64), unique=True)

    # MFA - one time recovery codes - comma separated.
    mf_recovery_codes: Mapped[list[str] | None] = mapped_column(
        MutableList.as_mutable(AsaList())
    )

    @declared_attr
    def roles(cls):
        # The first arg is a class name, the backref is a column name
        return relationship(
            "Role",
            secondary="roles_users",
            back_populates="users",
        )

    create_datetime: Mapped[datetime.datetime] = mapped_column(
        server_default=func.now()
    )
    update_datetime: Mapped[datetime.datetime] = mapped_column(
        server_default=func.now(),
        onupdate=naive_utcnow,
    )


class FsWebAuthnMixin(WebAuthnMixin):
    """WebAuthn"""

    id: Mapped[int] = mapped_column(primary_key=True)
    credential_id: Mapped[bytes] = mapped_column(
        LargeBinary(1024), index=True, unique=True
    )
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int | None] = mapped_column(default=0)
    transports: Mapped[list[str] | None] = mapped_column(
        MutableList.as_mutable(AsaList())
    )
    backup_state: Mapped[bool] = mapped_column()  # Upcoming post V3 spec
    device_type: Mapped[str] = mapped_column(String(64))

    # a JSON string as returned from registration
    extensions: Mapped[str | None] = mapped_column(String(255))
    create_datetime: Mapped[datetime.datetime] = mapped_column(
        server_default=func.now()
    )
    lastuse_datetime: Mapped[datetime.datetime] = mapped_column()
    # name is provided by user - we make sure is unique per user
    name: Mapped[str] = mapped_column(String(64))

    # Usage - a credential can EITHER be for first factor or secondary factor
    usage: Mapped[str] = mapped_column(String(64))

    try:
        import webauthn as webauthn_pkg

        @declared_attr
        def user(cls):
            return relationship("User", back_populates="webauthn")

    except ImportError:  # pragma: no cover
        pass

    @declared_attr
    def user_id(cls) -> Mapped[int]:
        return mapped_column(
            ForeignKey(f"{FsModels.user_table_name}.id", ondelete="CASCADE")
        )
