# Copyright 2021-2024 by J. Christopher Wagner (jwag). All rights reserved.

import typing as t

from flask import current_app
from werkzeug.local import LocalProxy

if t.TYPE_CHECKING:  # pragma: no cover
    from passlib.context import CryptContext
    from .core import Security, UserDatastore

# Convenient references
_security: "Security" = LocalProxy(  # type: ignore
    lambda: current_app.extensions["security"]
)

_datastore: "UserDatastore" = LocalProxy(  # type:ignore
    lambda: _security.datastore
)

_pwd_context: "CryptContext" = LocalProxy(lambda: _security.pwd_context)  # type: ignore

_hashing_context: "CryptContext" = LocalProxy(  # type: ignore
    lambda: _security.hashing_context
)

DecoratedView = t.Callable[..., t.Any]
