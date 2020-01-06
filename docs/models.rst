Models
======

Flask-Security assumes you'll be using libraries such as SQLAlchemy,
MongoEngine, Peewee or PonyORM to define a data model that includes a `User`
and `Role` model. The fields on your models must follow a particular convention
depending on the functionality your app requires. Aside from this, you're free
to add any additional fields to your model(s) if you want.

As more features are added to Flask-Security, the requirements for required fields and tables grow.
As you use these features, and therefore use these fields and tables, database migrations are required;
which are a bit of a pain. To make things easier - Flask-Security includes mixins that
contain ALL the fields and tables required for all features. They also contain
various `best practice` fields - such as update and create times. These mixins can
be easily extended to add any sort of custom fields and can be found in the
`models` module (today there is just one for using Flask-SqlAlchemy).

The provided models are versioned since they represent actual DB models, and any
changes require a schema migration (and perhaps a data migration). Applications
must specifically import the version they want (and handle any required migration).

At the bare minimum
your `User` and `Role` model should include the following fields:

**User**

* ``id``
* ``email``
* ``password``
* ``active``
* ``fs_uniquifier``


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

Passwordless
^^^^^^^^^^^^^

If you enable passwordless sign in by setting your application's `SECURITY_PASSWORDLESSV2`
configuration value to `True`, your `User` model will require the following
additional fields:

* ``pl_totp_secret``

If you include 'sms' in `SECURITY_PL_ENABLED_METHODS`, your `User` model
will require the following additional field:

* ``pl_phone_number``

Permissions
^^^^^^^^^^^
If you want to protect endpoints with permissions, and assign permissions to roles
that are then assigned to users the Role model requires:

* ``permissions``

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

