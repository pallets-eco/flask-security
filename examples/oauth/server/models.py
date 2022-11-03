"""
Copyright 2022 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.

"""

from flask_security.models import fsqla_v3 as fsqla
from flask_security import SQLAlchemyUserDatastore
from flask_sqlalchemy import SQLAlchemy

# Create database connection object
db = SQLAlchemy()

# Define models
fsqla.FsModels.set_db_info(db)


class Role(db.Model, fsqla.FsRoleMixin):
    pass


class User(db.Model, fsqla.FsUserMixin):
    pass


class WebAuthn(db.Model, fsqla.FsWebAuthnMixin):
    pass


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role, WebAuthn)
