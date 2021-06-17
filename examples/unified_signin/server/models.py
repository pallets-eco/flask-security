"""
Copyright 2019 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.

"""

from flask_security.models import fsqla_v2 as fsqla
from flask_security import SQLAlchemyUserDatastore
from flask_sqlalchemy import SQLAlchemy

# Create database connection object
db = SQLAlchemy()

# Define models
fsqla.FsModels.set_db_info(db)


class Role(db.Model, fsqla.FsRoleMixin):
    pass


class User(db.Model, fsqla.FsUserMixin):
    # Because we set "us_phone_number" as a USER_IDENTITY - it must be unique
    us_phone_number = db.Column(db.String(128), unique=True, nullable=True)


class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    text = db.Column(db.UnicodeText)


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
