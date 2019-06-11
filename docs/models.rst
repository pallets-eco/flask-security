Models
======

Flask-Security assumes you'll be using libraries such as SQLAlchemy,
MongoEngine, Peewee or PonyORM to define a data model that includes a `User`
and `Role` model. The fields on your models must follow a particular convention
depending on the functionality your app requires. Aside from this, you're free
to add any additional fields to your model(s) if you want. At the bare minimum
your `User` and `Role` model should include the following fields:

**User**

* ``id``
* ``email``
* ``password``
* ``active``


**Role**

* ``id``
* ``name``
* ``description``


Additional Functionality
------------------------

Depending on the application's configuration, additional fields may need to be
added to your `User` model.

Confirmable
^^^^^^^^^^^

If you enable account confirmation by setting your application's
`SECURITY_CONFIRMABLE` configuration value to `True`, your `User` model will
require the following additional field:

* ``confirmed_at``

Trackable
^^^^^^^^^

If you enable user tracking by setting your application's `SECURITY_TRACKABLE`
configuration value to `True`, your `User` model will require the following
additional fields:

* ``last_login_at``
* ``current_login_at``
* ``last_login_ip``
* ``current_login_ip``
* ``login_count``

Two_Factor
^^^^^^^^^^

If you enable two-factor by setting your application's `SECURITY_TWO_FACTOR`
configuration value to `True`, your `User` model will require the following
additional fields:

* ``tf_totp_secret``
* ``tf_primary_method``

If you include 'sms' in `SECURITY_TWO_FACTOR_ENABLED_METHODS`, your `User` model
will require the following additional field:

* ``tf_phone_number``

Custom User Payload
^^^^^^^^^^^^^^^^^^^

If you want a custom payload for JSON API responses, define
the method `get_security_payload` in your User model. The method must return a
serializable object:

.. code-block:: python

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        email = TextField()
        password = TextField()
        active = BooleanField(default=True)
        confirmed_at = DateTimeField(null=True)
        name = db.Column(db.String(80))

        # Custom User Payload
        def get_security_payload(self):
            return {
                'id': self.id,
                'name': self.name,
                'email': self.email
            }

