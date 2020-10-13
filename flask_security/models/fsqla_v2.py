"""
Copyright 2020 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.


Complete models for all features when using Flask-SqlAlchemy

BE AWARE: Once any version of this is shipped no changes can be made - instead
a new version needs to be created.

This is Version 2:
    - Add support for unified sign in.
    - Make username unique (but not required).
"""

from sqlalchemy import Column, String, Text
from sqlalchemy.ext.declarative import declared_attr


from .fsqla import FsModels as FsModelsV1
from .fsqla import FsUserMixin as FsUserMixinV1
from .fsqla import FsRoleMixin as FsRoleMixinV1


class FsModels(FsModelsV1):
    fs_model_version = 2
    pass


class FsRoleMixin(FsRoleMixinV1):
    pass


class FsUserMixin(FsUserMixinV1):
    """User information"""

    # Make username unique but not required.
    username = Column(String(255), unique=True, nullable=True)

    # unified sign in
    us_totp_secrets = Column(Text, nullable=True)
    us_phone_number = Column(String(128), nullable=True)

    # This is repeated since I couldn't figure out how to have it reference the
    # new version of FsModels.
    @declared_attr
    def roles(cls):
        return FsModels.db.relationship(
            "Role",
            secondary=FsModels.roles_users,
            backref=FsModels.db.backref("users", lazy="dynamic"),
        )
