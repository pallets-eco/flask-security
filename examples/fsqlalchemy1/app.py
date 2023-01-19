"""
Copyright 2019-2022 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.

Very simple application.
Uses built-in models.
Shows using roles and permissions to protect endpoints.

You can run the flask cli against this as well (once you have first created a
real DB) (from top level directory):
PYTHONPATH=. SQLALCHEMY_DATABASE_URI="sqlite:////var/tmp/test.db" \
 FLASK_APP=examples/fsqlalchemy1/app.py \
 flask users create -a test@me.com
"""

import os
import typing as t

from flask import Flask, abort, current_app, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_babel import Babel
from sqlalchemy import Column, ForeignKey, Integer, Text, UnicodeText
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

# Create database connection object
db = SQLAlchemy()

# Define models - for this example - we change the default table names
fsqla.FsModels.set_db_info(db, user_table_name="myuser", role_table_name="myrole")


class Role(db.Model, fsqla.FsRoleMixin):
    __tablename__ = "myrole"


class User(db.Model, fsqla.FsUserMixin):
    __tablename__ = "myuser"
    blogs: db.Mapped[t.List["Blog"]] = db.relationship(
        "Blog", back_populates="user", lazy="dynamic", cascade_backrefs=False
    )


class Blog(db.Model):
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("myuser.id"), nullable=False)
    user: db.Mapped["User"] = db.relationship(
        "User", back_populates="blogs", cascade_backrefs=False
    )
    title = Column(Text)
    text = Column(UnicodeText)


# Create app
def create_app():
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

    # Allow registration of new users without confirmation
    app.config["SECURITY_REGISTERABLE"] = True

    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "SQLALCHEMY_DATABASE_URI", "sqlite://"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # As of Flask-SQLAlchemy 2.4.0 it is easy to pass in options directly to the
    # underlying engine. This option makes sure that DB connections from the pool
    # are still valid. Important for entire application since many DBaaS options
    # automatically close idle connections.
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

    # Setup Flask-Security
    db.init_app(app)
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(app, user_datastore)

    # Setup Babel - not strictly necessary but since our virtualenv has Flask-Babel
    # we need to initialize it
    Babel(app)

    # Set this so unit tests can mock out.
    app.blog_cls = Blog

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
        blog = current_app.blog_cls.query.filter_by(id=bid).first()
        if not blog:
            abort(404)
        if current_user != blog.user:
            abort(403)
        return render_template_string("Yes, {{ current_user.email }} can update blog")

    @app.route("/myblogs", methods=["GET"])
    @auth_required()
    @permissions_accepted("user-read")
    def list_my_blogs():
        blogs = current_user.blogs
        blist = ""
        cnt = 0
        for blog in blogs:
            blist += f" {blog.title}"
            cnt += 1
        if not blogs:
            abort(404)
        return render_template_string(f"Found {cnt} of yours with titles {blist}")

    return app


# Create users and roles (and first blog!)
def create_users():
    if current_app.testing:
        return
    with current_app.app_context():
        security = current_app.security
        security.datastore.db.create_all()
        security.datastore.find_or_create_role(
            name="admin",
            permissions={"admin-read", "admin-write", "user-read", "user-write"},
        )
        security.datastore.find_or_create_role(
            name="monitor", permissions={"admin-read", "user-read"}
        )
        security.datastore.find_or_create_role(
            name="user", permissions={"user-read", "user-write"}
        )
        security.datastore.find_or_create_role(name="reader", permissions={"user-read"})

        if not security.datastore.find_user(email="admin@me.com"):
            security.datastore.create_user(
                email="admin@me.com",
                password=hash_password("password"),
                roles=["admin"],
            )
        if not security.datastore.find_user(email="ops@me.com"):
            security.datastore.create_user(
                email="ops@me.com",
                password=hash_password("password"),
                roles=["monitor"],
            )
        real_user = security.datastore.find_user(email="user@me.com")
        if not real_user:
            real_user = security.datastore.create_user(
                email="user@me.com", password=hash_password("password"), roles=["user"]
            )
        if not security.datastore.find_user(email="reader@me.com"):
            security.datastore.create_user(
                email="reader@me.com",
                password=hash_password("password"),
                roles=["reader"],
            )

        # create initial blog
        blog = current_app.blog_cls(
            title="First Blog", text="my first blog is short", user=real_user
        )
        security.datastore.db.session.add(blog)
        security.datastore.db.session.commit()
        print(f"First blog id {blog.id}")


if __name__ == "__main__":
    myapp = create_app()
    with myapp.app_context():
        create_users()
    myapp.run(port=5003)
