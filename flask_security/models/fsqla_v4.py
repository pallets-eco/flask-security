"""
Copyright 2026-2026 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.


Complete models for all features when using Flask-SqlAlchemy

BE AWARE: Once any version of this is shipped no changes can be made - instead
a new version needs to be created.

This is Version 4:
    - Add support for refresh tokens
"""

# mypy: disable-error-code="assignment"
# pyright: reportAssignmentType = false, reportIncompatibleVariableOverride=false

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    func,
)
from sqlalchemy.ext.declarative import declared_attr

from .fsqla import FsModels
from .fsqla_v3 import FsUserMixin as FsUserMixinV3
from .fsqla_v3 import FsRoleMixin as FsRoleMixinV3
from .fsqla_v3 import FsWebAuthnMixin as FsWebAuthnMixinV3
from flask_security import RefreshTrackerMixin

FsModels.fs_model_version = 4


class FsRoleMixin(FsRoleMixinV3):
    pass


class FsWebAuthnMixin(FsWebAuthnMixinV3):
    pass


class FsUserMixin(FsUserMixinV3):
    """User information"""

    @declared_attr
    def refresh_trackers(cls):
        return FsModels.db.relationship("FsRefreshTracker", cascade="all, delete")


class FsRefreshTrackerMixin(RefreshTrackerMixin):
    """Refresh Token Tracker"""

    id = Column(Integer, primary_key=True)
    # family and gen track refresh rotation
    refresh_family = Column(String(64), unique=True, nullable=False)
    gen = Column(Integer, default=1)
    expires_at = Column(type_=DateTime, nullable=False)
    revoked_at = Column(type_=DateTime, nullable=True)
    last_used_at = Column(type_=DateTime, nullable=False)
    create_datetime = Column(type_=DateTime, nullable=False, server_default=func.now())
    # name TODO - how to use/initialize it
    name = Column(String(64), nullable=False)

    @declared_attr
    def user_id(cls):
        return Column(
            Integer,
            ForeignKey(f"{FsModels.user_table_name}.id", ondelete="CASCADE"),
            nullable=False,
        )
