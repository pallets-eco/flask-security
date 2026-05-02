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

# mypy: disable-error-code="assignment"
# pyright: reportAssignmentType = false, reportIncompatibleVariableOverride=false

from sqlalchemy import Column, String, Text


from .fsqla import FsModels
from .fsqla import FsUserMixin as FsUserMixinV1
from .fsqla import FsRoleMixin as FsRoleMixinV1

FsModels.fs_model_version = 2


class FsRoleMixin(FsRoleMixinV1):
    pass


class FsUserMixin(FsUserMixinV1):
    """User information"""

    # Make username unique but not required.
    username = Column(String(255), unique=True, nullable=True)

    # unified sign in
    us_totp_secrets = Column(Text, nullable=True)
    us_phone_number = Column(String(128), nullable=True)
