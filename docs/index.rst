.. rst-class:: hide-header


Welcome to Flask-Security
=========================

.. image:: _static/logo-owl-full-240.png
    :alt: Flask-Security: add a drop of security to your Flask application.
    :align: left
    :width: 100%
    :target: https://github.com/pallets-eco/flask-security


Flask-Security allows you to quickly add common security mechanisms to your
Flask application. They include:

1. Authentication (via session, Basic HTTP, or token)
2. User registration (optional)
3. Role and Permission management
4. Account activation (via email confirmation) (optional)
5. Password management (recovery and resetting) (optional)
6. Two-factor authentication (optional)
7. WebAuthn Support (optional)
8. Use 'social'/Oauth for authentication (e.g. google, github, ..) (optional)
9. Change email (optional)
10. Login tracking (optional)
11. JSON/Ajax Support


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
4. `PonyORM <https://pypi.python.org/pypi/pony/>`_ - NOTE: not currently working - Help needed!.
5. `SQLAlchemy sessions <https://docs.sqlalchemy.org/en/20/orm/session_basics.html>`_
6. `Flask-SQLAlchemy-Lite <https://pypi.python.org/pypi/flask-sqlalchemy-lite/>`_


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
   `OpenApi Spec`_


.. _OpenApi Spec: _static/openapi_view.html

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
