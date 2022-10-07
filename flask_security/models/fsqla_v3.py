"""
Copyright 2021-2022 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.


Complete models for all features when using Flask-SqlAlchemy

BE AWARE: Once any version of this is shipped no changes can be made - instead
a new version needs to be created.

This is Version 3:
    - Add support for webauthn.
    - Add support for 2FA recovery codes.
    - password can be null.
    - us_phone_number must be unique.
    - Add support for list types.
"""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
)
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.sql import func


from .fsqla_v2 import FsModels as FsModelsV2
from .fsqla_v2 import FsUserMixin as FsUserMixinV2
from .fsqla_v2 import FsRoleMixin as FsRoleMixinV2
from flask_security import AsaList, WebAuthnMixin


class FsModels(FsModelsV2):
    fs_model_version = 3


class FsRoleMixin(FsRoleMixinV2):
    pass


class FsUserMixin(FsUserMixinV2):
    """User information"""

    try:
        import webauthn as webauthn_pkg

        # List of WebAuthn registrations
        @declared_attr
        def webauthn(cls):
            return FsModels.db.relationship(
                "WebAuthn", backref="users", cascade="all, delete"
            )

    except ImportError:
        pass

    # The user handle as required during registration.
    # Note max length 64 as specified in spec.
    fs_webauthn_user_handle = Column(String(64), unique=True, nullable=True)

    # MFA - one time recovery codes - comma separated.
    mf_recovery_codes = Column(MutableList.as_mutable(AsaList()), nullable=True)

    # Change password to nullable so we can tell after registration whether
    # a user has a password or not.
    password = Column(String(255), nullable=True)

    # since phone can be used to authenticate - must be unique.
    us_phone_number = Column(String(128), nullable=True, unique=True)

    # This is repeated since I couldn't figure out how to have it reference the
    # new version of FsModels.
    @declared_attr
    def roles(cls):
        return FsModels.db.relationship(
            "Role",
            secondary=FsModels.roles_users,
            backref=FsModels.db.backref(
                "users", lazy="dynamic", cascade_backrefs=False
            ),
        )


class FsWebAuthnMixin(WebAuthnMixin):
    """WebAuthn"""

    id = Column(Integer, primary_key=True)
    credential_id = Column(LargeBinary(1024), index=True, unique=True, nullable=False)
    public_key = Column(LargeBinary, nullable=False)
    sign_count = Column(Integer, default=0)
    transports = Column(MutableList.as_mutable(AsaList()), nullable=True)
    backup_state = Column(Boolean, nullable=False)  # Upcoming post V3 spec
    device_type = Column(String(64), nullable=False)

    # a JSON string as returned from registration
    extensions = Column(String(255), nullable=True)
    create_datetime = Column(type_=DateTime, nullable=False, server_default=func.now())
    lastuse_datetime = Column(type_=DateTime, nullable=False)
    # name is provided by user - we make sure is unique per user
    name = Column(String(64), nullable=False)

    # Usage - a credential can EITHER be for first factor or secondary factor
    usage = Column(String(64), nullable=False)

    @declared_attr
    def user_id(cls):
        return Column(
            Integer,
            ForeignKey(f"{FsModels.user_table_name}.id", ondelete="CASCADE"),
            nullable=False,
        )
