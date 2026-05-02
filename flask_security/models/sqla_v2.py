"""
Copyright 2026-2026 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.


Complete models for all features when using SqlAlchemy.
These are pure sqlalchemy declarative models - so should work with Flask-SQLAlchemy-Lite
as well as just sqlalchemy (such as using a scoped session).

You can change the table names by passing them in to the set_db_info() method.

BE AWARE: Once any version of this is shipped no changes can be made - instead
a new version needs to be created.

This is Version 2:
    - Add support for refresh tokens
"""

# mypy: disable-error-code="assignment"
# pyright: reportAssignmentType = false, reportIncompatibleVariableOverride=false

from __future__ import annotations

import datetime

from sqlalchemy import (
    String,
    ForeignKey,
    func,
)
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import Mapped, mapped_column, relationship

from flask_security import RefreshTrackerMixin

from .sqla import FsModels
from .sqla import FsUserMixin as FsUserMixinV1
from .sqla import FsRoleMixin as FsRoleMixinV1
from .sqla import FsWebAuthnMixin as FsWebauthnMixinV1

FsModels.fs_model_version = 2


class FsRoleMixin(FsRoleMixinV1):
    pass


class FsUserMixin(FsUserMixinV1):
    """User information"""

    # List of Refresh Token trackers
    @declared_attr
    def refresh_trackers(cls):
        return relationship("FsRefreshTracker", cascade="all, delete")


class FsWebAuthnMixin(FsWebauthnMixinV1):
    pass


class FsRefreshTrackerMixin(RefreshTrackerMixin):
    """Refresh Token Tracker"""

    id: Mapped[int] = mapped_column(primary_key=True)
    # family and gen track refresh rotation
    refresh_family: Mapped[str] = mapped_column(String(64), unique=True)
    gen: Mapped[int] = mapped_column()
    expires_at: Mapped[datetime.datetime] = mapped_column()
    revoked_at: Mapped[datetime.datetime | None] = mapped_column()
    last_used_at: Mapped[datetime.datetime] = mapped_column()
    create_datetime: Mapped[datetime.datetime] = mapped_column(
        server_default=func.now()
    )
    # name TODO - how to use/initialize it
    name: Mapped[str] = mapped_column(String(64))

    @declared_attr
    def user_id(cls) -> Mapped[int]:
        return mapped_column(
            ForeignKey(f"{FsModels.user_table_name}.id", ondelete="CASCADE")
        )
