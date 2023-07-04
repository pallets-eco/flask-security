.. rst-class:: hide-header


Welcome to Flask-Security
=========================

.. image:: _static/logo-owl-full-240.png
    :alt: Flask-Security: add a drop of security to your Flask application.
    :align: left
    :width: 100%
    :target: https://github.com/Flask-Middleware/flask-security


Flask-Security allows you to quickly add common security mechanisms to your
Flask application. They include:

1. Session based authentication
2. Role and Permission management
3. Password hashing
4. Basic HTTP authentication
5. Token based authentication
6. Token based account activation (optional)
7. Token based password recovery / resetting (optional)
8. Two-factor authentication (optional)
9. Unified sign in (optional)
10. User registration (optional)
11. Login tracking (optional)
12. JSON/Ajax Support
13. WebAuthn Support (optional)
14. Use 'social'/Oauth for authentication (e.g. google, github, ..) (optional)

Many of these features are made possible by integrating various Flask extensions
and libraries. They include:

* `Flask-Login <https://flask-login.readthedocs.org/en/latest/>`_
* `Flask-Mailman <https://pypi.org/project/Flask-Mailman/>`_
* `Flask-Principal <https://pypi.org/project/Flask-Principal/>`_
* `Flask-WTF <https://pypi.org/project/Flask-WTF/>`_
* `itsdangerous <https://pypi.org/project/itsdangerous/>`_
* `passlib <https://pypi.org/project/passlib/>`_
* `QRCode <https://pypi.org/project/qrcode/>`_
* `webauthn <https://pypi.org/project/webauthn/>`_
* `authlib <https://pypi.org/project/Authlib/>`_

Additionally, it assumes you'll be using a common library for your database
connections and model definitions. Flask-Security supports the following Flask
extensions out of the box for data persistence:

1. `Flask-SQLAlchemy <https://pypi.python.org/pypi/flask-sqlalchemy/>`_
2. `MongoEngine <https://pypi.python.org/pypi/mongoengine/>`_
3. `Peewee Flask utils <https://docs.peewee-orm.com/en/latest/peewee/playhouse.html#flask-utils>`_
4. `PonyORM <https://pypi.python.org/pypi/pony/>`_ - NOTE: not currently supported.
5. `SQLAlchemy sessions <https://docs.sqlalchemy.org/en/14/orm/session_basics.html>`_


Getting Started
----------------

.. toctree::
   :maxdepth: 2

   installation
   quickstart
   features
   configuration
   models

Customizing and Usage Patterns
-------------------------------

.. toctree::
   :maxdepth: 2

   customizing
   webauthn
   two_factor_configurations
   spa
   patterns

API
---

.. toctree::
   :maxdepth: 2

   api

Additional Notes
----------------

.. toctree::
   :maxdepth: 2

   contributing
   changelog
   authors
