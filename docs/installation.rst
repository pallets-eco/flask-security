Installation
=============

Installing Flask-Security-Too using::

    pip install flask-security-too

will install the basic package along with its required dependencies:

* Flask
* Flask-Login
* Flask-Principal
* Flask-WTF
* email-validator
* itsdangerous
* passlib
* Blinker

These are not sufficient for a complete application - other packages are
required based on features desired, password hash algorithms, storage backend, etc.
Flask-Security-Too has additional distribution 'extras' that can reduce the hassle
of figuring out all the required packages. You can install these using the
standard pip syntax::

    pip install flask-security-too[extra1,extra2, ...]

Supported extras are:

* ``babel`` - Translation services. It will install babel and Flask-Babel.
* ``fsqla`` - Use flask-sqlalchemy and sqlalchemy as your storage interface.
* ``common`` - Install Flask-Mail, and bcrypt (the default password hash).
* ``mfa`` - Install packages used for multi-factor (two-factor and unified signin):
  cryptography, pyqrcode, phonenumberslite (note that for SMS you still need
  to pick an SMS provider and install appropriate packages).

Your application will also need a database backend:

* Sqlite is supported out of the box.
* For PostgreSQL install `psycopg2`_.
* For MySQL install `pymysql`_.
* For MongoDB install `Flask-Mongoengine`_.

For additional details on configuring your database engine connector - refer to `sqlalchemy_engine`_

.. _psycopg2: https://pypi.org/project/psycopg2/
.. _pymysql: https://pypi.org/project/PyMySQL/
.. _Flask-Mongoengine: https://pypi.org/project/flask-mongoengine/
.. _sqlalchemy_engine: https://docs.sqlalchemy.org/en/14/core/engines.html
