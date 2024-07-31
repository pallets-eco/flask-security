Quick Start
===========

There are some complete (but simple) examples available in the *examples* directory of the
`Flask-Security repo`_.

.. note::
    The below quickstarts are just that - they don't enable most of the features (such as registration, reset, etc.).
    They basically create a single user, and you can login as that user... that's it.
    As you add more features, additional packages (e.g. Flask-Mailman, Flask-Babel, qrcode) might be required
    and will need to be added to your requirements.txt (or equivalent) file.
    Flask-Security does some configuration validation and will output error messages to the console
    for some missing packages.
.. note::
    The sqlalchemy based quickstarts all use the pre-packaged models - because, well, that's
    the quickest and easiest way to get started. There is NO REQUIREMENT that your application
    use these - as long as the required fields are in your models.

.. note::
    The default :data:`SECURITY_PASSWORD_HASH` is "argon2" - so be sure to install `argon2_cffi`_.
    If you opt for a different hash e.g. "bcrypt" you will need to install the appropriate package.
.. danger::
   The examples below place secrets in source files. Never do this for your application
   especially if your source code is placed in a public repo. How you pass in secrets
   securely will depend on your deployment model - however in most cases (e.g. docker, lambda)
   using environment variables will be the easiest.

.. _argon2_cffi: https://pypi.org/project/argon2-cffi/

* :ref:`basic-flask-sqlalchemy-application`
* :ref:`basic-flask-sqlalchemy-lite-application`
* :ref:`basic-sqlalchemy-application-with-session`
* :ref:`basic-mongoengine-application`
* :ref:`basic-peewee-application`
* :ref:`mail-configuration`
* :ref:`proxy-configuration`
* :ref:`unit-testing`

.. _basic-flask-sqlalchemy-application:

Basic Flask-SQLAlchemy Application
-----------------------------------

Flask-SQLAlchemy Install requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

     $ python3 -m venv pymyenv
     $ . pymyenv/bin/activate
     $ pip install flask-security[fsqla,common]


Flask-SQLAlchemy Application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code sample illustrates how to get started as quickly as
possible using Flask-SQLAlchemy and the built-in model mixins.

.. code-block:: python

    import os

    from flask import Flask, render_template_string
    from flask_sqlalchemy import SQLAlchemy
    from flask_security import Security, SQLAlchemyUserDatastore, auth_required, hash_password
    from flask_security.models import fsqla_v3 as fsqla

    # Create app
    app = Flask(__name__)
    app.config['DEBUG'] = True

    # Generate a nice key using secrets.token_urlsafe()
    app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", 'pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw')
    # Generate a good salt for password hashing using: secrets.SystemRandom().getrandbits(128)
    app.config['SECURITY_PASSWORD_SALT'] = os.environ.get("SECURITY_PASSWORD_SALT", '146585145368132386173505678016728509634')

    # have session and remember cookie be samesite (flask/flask_login)
    app.config["REMEMBER_COOKIE_SAMESITE"] = "strict"
    app.config["SESSION_COOKIE_SAMESITE"] = "strict"

    # Use an in-memory db
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
    # As of Flask-SQLAlchemy 2.4.0 it is easy to pass in options directly to the
    # underlying engine. This option makes sure that DB connections from the
    # pool are still valid. Important for entire application since
    # many DBaaS options automatically close idle connections.
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
    }
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Create database connection object
    db = SQLAlchemy(app)

    # Define models
    fsqla.FsModels.set_db_info(db)

    class Role(db.Model, fsqla.FsRoleMixin):
        pass

    class User(db.Model, fsqla.FsUserMixin):
        pass

    # Setup Flask-Security
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security = Security(app, user_datastore)

    # Views
    @app.route("/")
    @auth_required()
    def home():
        return render_template_string("Hello {{ current_user.email }}")

    # one time setup
    with app.app_context():
        # Create User to test with
        db.create_all()
        if not security.datastore.find_user(email="test@me.com"):
            security.datastore.create_user(email="test@me.com", password=hash_password("password"))
        db.session.commit()

    if __name__ == '__main__':
        app.run()

You can run this either with::

    flask run

or::

    python app.py

.. _basic-flask-sqlalchemy-lite-application:

Basic Flask-SQLAlchemy-Lite Application
----------------------------------------

Flask-SQLAlchemy Install requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This requires python >= 3.10::

     $ python3 -m venv pymyenv
     $ . pymyenv/bin/activate
     $ pip install flask-security[common] sqlalchemy flask-sqlalchemy-lite

Flask-SQLAlchemy-Lite Application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code sample illustrates how to get started as quickly as
possible using Flask-SQLAlchemy-Lite and the built-in model mixins.
Note that Flask-SQLAlchemy-Lite is a very thin wrapper above sqlalchemy.orm
and just provides session and engine initialization. Everything else is
pure sqlalchemy (unlike Flask-SQLAlchemy).

.. code-block:: python

    import os

    from flask import Flask, render_template_string
    from flask_sqlalchemy_lite import SQLAlchemy
    from flask_security import Security, SQLAlchemyUserDatastore, auth_required, hash_password
    from flask_security.models import sqla as sqla

    # Create app
    app = Flask(__name__)
    app.config['DEBUG'] = True

    # Generate a nice key using secrets.token_urlsafe()
    app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", 'pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw')
    # Generate a good salt for password hashing using: secrets.SystemRandom().getrandbits(128)
    app.config['SECURITY_PASSWORD_SALT'] = os.environ.get("SECURITY_PASSWORD_SALT", '146585145368132386173505678016728509634')

    # have session and remember cookie be samesite (flask/flask_login)
    app.config["REMEMBER_COOKIE_SAMESITE"] = "strict"
    app.config["SESSION_COOKIE_SAMESITE"] = "strict"

    # Use an in-memory db
    app.config |= {
        "SQLALCHEMY_ENGINES": {
            "default": {"url": "sqlite:///:memory:", "pool_pre_ping": True},
        },
    }

    # Create database connection object
    db = SQLAlchemy(app)

    # Define models
    class Model(DeclarativeBase):
        pass

    # NOTE: call this PRIOR to declaring models
    sqla.FsModels.set_db_info(base_model=Model)

    class Role(Model, sqla.FsRoleMixin):
        __tablename__ = "Role"
        pass

    class User(Model, sqla.FsUserMixin):
        __tablename__ = "User"
        pass

    # Setup Flask-Security
    user_datastore = FSQLALiteUserDatastore(db, User, Role)
    security = Security(app, user_datastore)

    # Views
    @app.route("/")
    @auth_required()
    def home():
        return render_template_string("Hello {{ current_user.email }}")

    # one time setup
    with app.app_context():
        # Create User to test with
        Model.metadata.create_all(db.engine)
        if not security.datastore.find_user(email="test@me.com"):
            security.datastore.create_user(email="test@me.com", password=hash_password("password"))
        db.session.commit()

    if __name__ == '__main__':
        app.run()

You can run this either with::

    flask run

or::

    python app.py

.. _basic-sqlalchemy-application-with-session:

Basic SQLAlchemy Application with session
-----------------------------------------

SQLAlchemy Install requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This requires python >= 3.10::

     $ python3 -m venv pymyenv
     $ . pymyenv/bin/activate
     $ pip install flask-security[common] sqlalchemy

SQLAlchemy Application (w/o Flask-SQLAlchemy)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code sample illustrates how to get started as quickly as
possible using `SQLAlchemy in a declarative way
<https://flask.palletsprojects.com/en/2.0.x/patterns/sqlalchemy/#declarative>`_:

This example shows how to split your application into 3 files: app.py, database.py
and models.py.

- app.py
    .. code-block:: python

        import os

        from flask import Flask, render_template_string
        from flask_security import Security, current_user, auth_required, hash_password, \
             SQLAlchemySessionUserDatastore, permissions_accepted
        from database import db_session, init_db
        from models import User, Role

        # Create app
        app = Flask(__name__)
        app.config['DEBUG'] = True

        # Generate a nice key using secrets.token_urlsafe()
        app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", 'pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw')
        # Generate a good salt for password hashing using: secrets.SystemRandom().getrandbits(128)
        app.config['SECURITY_PASSWORD_SALT'] = os.environ.get("SECURITY_PASSWORD_SALT", '146585145368132386173505678016728509634')
        # Don't worry if email has findable domain
        app.config["SECURITY_EMAIL_VALIDATOR_ARGS"] = {"check_deliverability": False}

        # manage sessions per request - make sure connections are closed and returned
        app.teardown_appcontext(lambda exc: db_session.close())

        # Setup Flask-Security
        user_datastore = SQLAlchemySessionUserDatastore(db_session, User, Role)
        security = Security(app, user_datastore)

        # Views
        @app.route("/")
        @auth_required()
        def home():
            return render_template_string('Hello {{current_user.email}}!')

        @app.route("/user")
        @auth_required()
        @permissions_accepted("user-read")
        def user_home():
            return render_template_string("Hello {{ current_user.email }} you are a user!")

        # one time setup
        with app.app_context():
            init_db()
            # Create a user and role to test with
            security.datastore.find_or_create_role(
                name="user", permissions={"user-read", "user-write"}
            )
            db_session.commit()
            if not security.datastore.find_user(email="test@me.com"):
                security.datastore.create_user(email="test@me.com",
                password=hash_password("password"), roles=["user"])
            db_session.commit()

        if __name__ == '__main__':
            # run application (can also use flask run)
            app.run()

- database.py
    .. code-block:: python

        from sqlalchemy import create_engine
        from sqlalchemy.orm import scoped_session, sessionmaker
        from sqlalchemy.ext.declarative import declarative_base
        from flask_security.models import sqla

        engine = create_engine('sqlite:////tmp/test.db')
        db_session = scoped_session(sessionmaker(autocommit=False,
                                                 autoflush=False,
                                                 bind=engine))
        Base = declarative_base()
        # This creates the RolesUser table and is where
        # you would pass in non-standard tables names.
        sqla.FsModels.set_db_info(base_model=Base)


        def init_db():
            # import all modules here that might define models so that
            # they will be registered properly on the metadata.  Otherwise
            # you will have to import them first before calling init_db()
            import models
            Base.metadata.create_all(bind=engine)

- models.py
    .. code-block:: python

        from database import Base
        from flask_security.models import sqla as sqla

        class Role(Base, sqla.FsRoleMixin):
            __tablename__ = 'role'

        class User(Base, sqla.FsUserMixin):
            __tablename__ = 'user'

You can run this either with::

    flask run

or::

    python app.py

.. _basic-mongoengine-application:

Basic MongoEngine Application
-----------------------------

MongoEngine Install requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    $ python3 -m venv pymyenv
    $ . pymyenv/bin/activate
    $ pip install flask-security[common] mongoengine

MongoEngine Application
~~~~~~~~~~~~~~~~~~~~~~~

The following code sample illustrates how to get started as quickly as
possible using MongoEngine (of course you have to install and start up a
local MongoDB instance).

.. code-block:: python

    import os

    from flask import Flask, render_template_string
    from mongoengine import Document, connect
    from mongoengine.fields import (
        BinaryField,
        BooleanField,
        DateTimeField,
        IntField,
        ListField,
        ReferenceField,
        StringField,
    )
    from flask_security import Security, MongoEngineUserDatastore, \
        UserMixin, RoleMixin, auth_required, hash_password, permissions_accepted

    # Create app
    app = Flask(__name__)
    app.config['DEBUG'] = True

    # Generate a nice key using secrets.token_urlsafe()
    app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", 'pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw')
    # Generate a good salt for password hashing using: secrets.SystemRandom().getrandbits(128)
    app.config['SECURITY_PASSWORD_SALT'] = os.environ.get("SECURITY_PASSWORD_SALT", '146585145368132386173505678016728509634')
    # Don't worry if email has findable domain
    app.config["SECURITY_EMAIL_VALIDATOR_ARGS"] = {"check_deliverability": False}

    # Create database connection object
    db_name = "mydatabase"
    db = connect(alias=db_name, db=db_name, host="mongodb://localhost", port=27017)

    class Role(Document, RoleMixin):
        name = StringField(max_length=80, unique=True)
        description = StringField(max_length=255)
        permissions = ListField(required=False)
        meta = {"db_alias": db_name}

    class User(Document, UserMixin):
        email = StringField(max_length=255, unique=True)
        password = StringField(max_length=255)
        active = BooleanField(default=True)
        fs_uniquifier = StringField(max_length=64, unique=True)
        confirmed_at = DateTimeField()
        roles = ListField(ReferenceField(Role), default=[])
        meta = {"db_alias": db_name}

    # Setup Flask-Security
    user_datastore = MongoEngineUserDatastore(db, User, Role)
    security = Security(app, user_datastore)

    # Views
    @app.route("/")
    @auth_required()
    def home():
        return render_template_string("Hello {{ current_user.email }}")

    @app.route("/user")
    @auth_required()
    @permissions_accepted("user-read")
    def user_home():
        return render_template_string("Hello {{ current_user.email }} you are a user!")

    # one time setup
    with app.app_context():
        # Create a user and role to test with
        security.datastore.find_or_create_role(
            name="user", permissions={"user-read", "user-write"}
        )
        if not security.datastore.find_user(email="test@me.com"):
            security.datastore.create_user(email="test@me.com",
            password=hash_password("password"), roles=["user"])

    if __name__ == '__main__':
        # run application (can also use flask run)
        app.run()


.. _basic-peewee-application:

Basic Peewee Application
------------------------

Peewee Install requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    $ python3 -m venv pymyenv
    $ . pymyenv/bin/activate
    $ pip install flask-security[common] peewee

Peewee Application
~~~~~~~~~~~~~~~~~~

The following code sample illustrates how to get started as quickly as
possible using Peewee.

.. code-block:: python

    import os

    from flask import Flask, render_template_string
    from playhouse.flask_utils import FlaskDB
    from peewee import *
    from flask_security import Security, PeeweeUserDatastore, \
        UserMixin, RoleMixin, auth_required, hash_password

    # Create app
    app = Flask(__name__)
    app.config['DEBUG'] = True

    # Generate a nice key using secrets.token_urlsafe()
    app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", 'pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw')
    # Generate a good salt for password hashing using: secrets.SystemRandom().getrandbits(128)
    app.config['SECURITY_PASSWORD_SALT'] = os.environ.get("SECURITY_PASSWORD_SALT", '146585145368132386173505678016728509634')

    app.config['DATABASE'] = {
        'name': 'example.db',
        'engine': 'peewee.SqliteDatabase',
    }

    # Create database connection object
    db = FlaskDB(app)

    class Role(RoleMixin, db.Model):
        name = CharField(unique=True)
        description = TextField(null=True)
        permissions = TextField(null=True)

    # N.B. order is important since db.Model also contains a get_id() -
    # we need the one from UserMixin.
    class User(UserMixin, db.Model):
        email = TextField()
        password = TextField()
        active = BooleanField(default=True)
        fs_uniquifier = TextField(null=False)
        confirmed_at = DateTimeField(null=True)

    class UserRoles(db.Model):
        # Because peewee does not come with built-in many-to-many
        # relationships, we need this intermediary class to link
        # user to roles.
        user = ForeignKeyField(User, related_name='roles')
        role = ForeignKeyField(Role, related_name='users')
        name = property(lambda self: self.role.name)
        description = property(lambda self: self.role.description)

        def get_permissions(self):
            return self.role.get_permissions()

    # Setup Flask-Security
    user_datastore = PeeweeUserDatastore(db, User, Role, UserRoles)
    security = Security(app, user_datastore)

    # Views
    @app.route('/')
    @auth_required()
    def home():
        return render_template_string("Hello {{ current_user.email }}")

    # one time setup
    with app.app_context():
        # Create a user to test with
        for Model in (Role, User, UserRoles):
            Model.drop_table(fail_silently=True)
            Model.create_table(fail_silently=True)
        if not security.datastore.find_user(email="test@me.com"):
            security.datastore.create_user(email="test@me.com", password=hash_password("password"))

    if __name__ == '__main__':
        app.run()


.. _mail-configuration:

Mail Configuration
------------------

Flask-Security integrates with an outgoing mail service via the ``mail_util_cls`` which
is part of initial configuration. The default class :class:`flask_security.MailUtil` utilizes the
`Flask-Mailman <https://pypi.org/project/flask-mailman/>`_ package. Be sure to add flask_mailman to
your requirements.txt. The older and no longer maintained package `Flask-Mail <https://pypi.org/project/Flask-Mail/>`_
is also (still) supported.

The following code illustrates a basic setup, which could be added to
the basic application code in the previous section::

    # At top of file
    from flask_mailman import Mail

    # After 'Create app'
    app.config['MAIL_SERVER'] = 'smtp.example.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'username'
    app.config['MAIL_PASSWORD'] = 'password'
    mail = Mail(app)

To learn more about the various Flask-Mailman settings to configure it to
work with your particular email server configuration, please see the
`Flask-Mailman documentation <https://waynerv.github.io/flask-mailman/>`_.

.. _proxy-configuration:

Proxy Configuration
-------------------

The user tracking features need an additional configuration
in HTTP proxy environment. The following code illustrates a setup
with a single HTTP proxy in front of the web application::

    # At top of file
    from werkzeug.middleware.proxy_fix import ProxyFix

    # After 'Create app'
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

To learn more about the ``ProxyFix`` middleware, please see the
`Werkzeug documentation <https://werkzeug.palletsprojects.com/en/2.0.x/middleware/proxy_fix/#module-werkzeug.middleware.proxy_fix>`_.

.. _unit-testing:

Unit Testing Your Application
-----------------------------

As soon as you add any of the Flask-Security decorators to your API endpoints, it can
be frustrating to unit test your basic routing (and roles and permissions). Without getting
into the argument of the difference between unit tests and integration tests - you can approach testing
in 2 ways:

* 'Pure' unit test - mocking out all lower level objects (such as the data store)
* Complete app with in-memory/temporary DB (with little or no mocking).

Look in the `Flask-Security repo`_ *examples* directory for actual code that implements the
second approach which is much simpler and with an in-memory DB fairly fast.

You also might want to set the following configurations in your conftest.py:

.. code-block:: python

    app.config["WTF_CSRF_ENABLED"] = False
    # Our test emails/domain isn't necessarily valid
    app.config["SECURITY_EMAIL_VALIDATOR_ARGS"] = {"check_deliverability": False}
    # Make this plaintext for most tests - reduces unit test time by 50%
    app.config["SECURITY_PASSWORD_HASH"] = "plaintext"

.. _Flask-Security repo: https://github.com/pallets-eco/flask-security
