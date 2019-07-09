Flask-Security
==============

Flask-Security allows you to quickly add common security mechanisms to your
Flask application. They include:

1. Session based authentication
2. Role and Permission management
3. Password hashing
4. Basic HTTP authentication
5. Token based authentication
6. Token based account activation (optional)
7. Token based password recovery / resetting (optional)
8. Two-factor authentication (optional/experimental)
9. User registration (optional)
10. Login tracking (optional)
11. JSON/Ajax Support

Many of these features are made possible by integrating various Flask extensions
and libraries. They include:

1. `Flask-Login <https://flask-login.readthedocs.org/en/latest/>`_
2. `Flask-Mail <https://pypi.org/project/Flask-Mail/>`_
3. `Flask-Principal <https://pypi.org/project/Flask-Principal/>`_
4. `Flask-WTF <https://pypi.org/project/Flask-WTF/>`_
5. `itsdangerous <https://pypi.org/project/itsdangerous/>`_
6. `passlib <https://pypi.org/project/passlib/>`_
7. `PyQRCode <https://pypi.org/project/PyQRCode/>`_

Additionally, it assumes you'll be using a common library for your database
connections and model definitions. Flask-Security supports the following Flask
extensions out of the box for data persistence:

1. `Flask-SQLAlchemy <http://pypi.python.org/pypi/flask-sqlalchemy/>`_
2. `Flask-MongoEngine <http://pypi.python.org/pypi/flask-mongoengine/>`_
3. `Flask-Peewee <http://pypi.python.org/pypi/flask-peewee/>`_
4. `PonyORM <http://pypi.python.org/pypi/pony/>`_


.. include:: contents.rst.inc
