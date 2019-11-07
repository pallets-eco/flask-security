"""
Copyright 2019 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.

Very simple application.
Uses built-in models.
Shows using roles and permissions to protect endpoints.

You can run the flask cli against this as well (once you have first created a
real DB):
SQLALCHEMY_DATABASE_URI="sqlite:////var/tmp/test.db" \
 FLASK_APP=examples/fsqlalchemy1/app.py \
 flask users create -a test@me.com
"""

import os

from flask import Flask, abort, current_app, render_template_string
from flask.json import JSONEncoder
from flask_sqlalchemy import SQLAlchemy
from flask_security import (
    Security,
    SQLAlchemyUserDatastore,
    auth_required,
    current_user,
    hash_password,
    permissions_accepted,
    permissions_required,
    roles_accepted,
)
from flask_security.models import fsqla_v2 as fsqla

# Create app
app = Flask(__name__)
app.config["DEBUG"] = True
# generated using: secrets.token_urlsafe()
app.config["SECRET_KEY"] = "pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw"
app.config["SECURITY_PASSWORD_HASH"] = "argon2"
# argon2 uses double hashing by default - so provide key.
# For python3: secrets.SystemRandom().getrandbits(128)
app.config["SECURITY_PASSWORD_SALT"] = "146585145368132386173505678016728509634"

# Take password complexity seriously
app.config["SECURITY_PASSWORD_COMPLEXITY_CHECKER"] = "zxcvbn"

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "SQLALCHEMY_DATABASE_URI", "sqlite://"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# As of Flask-SQLAlchemy 2.4.0 it is easy to pass in options directly to the
# underlying engine. This option makes sure that DB connections from the pool
# are still valid. Important for entire application since many DBaaS options
# automatically close idle connections.
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

app.json_encoder = JSONEncoder

# Create database connection object
db = SQLAlchemy(app)

# Define models
fsqla.FsModels.set_db_info(db)


class Role(db.Model, fsqla.FsRoleMixin):
    pass


class User(db.Model, fsqla.FsUserMixin):
    blogs = db.relationship("Blog", backref="user", lazy="dynamic")
    pass


class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    text = db.Column(db.UnicodeText)


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
app.security = Security(app, user_datastore)

# Set this so unit tests can mock out.
app.blog_cls = Blog


# Create users and roles (and first blog!)
@app.before_first_request
def create_users():
    if current_app.testing:
        return
    db.create_all()
    user_datastore.create_role(
        name="admin",
        permissions={"admin-read", "admin-write", "user-read", "user-write"},
    )
    user_datastore.create_role(name="monitor", permissions={"admin-read", "user-read"})
    user_datastore.create_role(name="user", permissions={"user-read", "user-write"})
    user_datastore.create_role(name="reader", permissions={"user-read"})

    user_datastore.create_user(
        email="admin@me.com", password=hash_password("password"), roles=["admin"]
    )
    user_datastore.create_user(
        email="ops@me.com", password=hash_password("password"), roles=["monitor"]
    )
    real_user = user_datastore.create_user(
        email="user@me.com", password=hash_password("password"), roles=["user"]
    )
    user_datastore.create_user(
        email="reader@me.com", password=hash_password("password"), roles=["reader"]
    )

    # create initial blog
    blog = app.blog_cls(text="my first blog", user=real_user)
    db.session.add(blog)
    db.session.commit()
    print("First blog id {}".format(blog.id))


# Views
# Note that we always add @auth_required so that if a client isn't logged in
# we will get a proper '401' and redirected to login page.
@app.route("/")
@auth_required()
def home():
    return render_template_string("Hello {{ current_user.email }}")


@app.route("/admin")
@auth_required()
@permissions_accepted("admin-read", "admin-write")
def admin():
    return render_template_string(
        "Hello on admin page. Current user {} password is {}".format(
            current_user.email, current_user.password
        )
    )


@app.route("/ops")
@auth_required()
@roles_accepted("monitor")
def monitor():
    # Example of using just a role. Note that 'admin' can't access this
    # since it doesn't have the 'monitor' role - even though it has
    # all the permissions that the 'monitor' role has.
    return render_template_string("Hello OPS")


@app.route("/blog/<bid>", methods=["GET", "POST"])
@auth_required()
@permissions_required("user-write")
def update_blog(bid):
    # Yes caller has write permission - but do they OWN this blog?
    blog = current_app.blog_cls.query.get(bid)
    if current_user != blog.user:
        abort(403)
    return render_template_string("Yes, {{ current_user.email }} can update blog")


if __name__ == "__main__":
    app.run(port=5001)
