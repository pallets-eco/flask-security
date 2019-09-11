Features
========

Flask-Security allows you to quickly add common security mechanisms to your
Flask application. They include:


Session Based Authentication
----------------------------

Session based authentication is fulfilled entirely by the `Flask-Login`_
extension. Flask-Security handles the configuration of Flask-Login automatically
based on a few of its own configuration values and uses Flask-Login's
`alternative token`_ feature for remembering users when their session has
expired. `Flask-WTF`_ integrates with the session as well to provide out of the box
CSRF support. Flask-Security extends that to support requiring CSRF for
requests that are authenticated via session cookies, but not for requests
authenticated using tokens.


Role/Identity Based Access
--------------------------

Flask-Security implements very basic role management out of the box. This means
that you can associate a high level role or multiple roles to any user. For
instance, you may assign roles such as `Admin`, `Editor`, `SuperUser`, or a
combination of said roles to a user. Access control is based on the role name and/or
permissions contained within the role;
and all roles should be uniquely named. This feature is implemented using the
`Flask-Principal`_ extension. As with basic RBAC, permissions can be assigned to roles
to provide more granular access control. Permissions can be associated with one or
more roles (the RoleModel contains a list of permissions). The values of
permissions are completely up to the developer - Flask-Security simply treats them
as strings.
If you'd like to implement even more granular access
control (such as per-object), you can refer to the Flask-Principal `documentation on this topic`_.


Password Hashing
----------------

Password hashing is enabled with `passlib`_. Passwords are hashed with the
`bcrypt`_ function by default but you can easily configure the hashing
algorithm. You should **always use a hashing algorithm** in your production
environment. You may also specify to use HMAC with a configured salt value in
addition to the algorithm chosen. Bear in mind passlib does not assume which
algorithm you will choose and may require additional libraries to be installed.


Basic HTTP Authentication
-------------------------

Basic HTTP authentication is achievable using a simple view method decorator.
This feature expects the incoming authentication information to identify a user
in the system. This means that the username must be equal to their email address.


Token Authentication
--------------------

Token based authentication is enabled by retrieving the user auth token by
performing an HTTP POST with a query param of ``include_auth_token`` with the authentication details
as JSON data against the
authentication endpoint. A successful call to this endpoint will return the
user's ID and their authentication token. This token can be used in subsequent
requests to protected resources. The auth token is supplied in the request
through an HTTP header or query string parameter. By default the HTTP header
name is `Authentication-Token` and the default query string parameter name is
`auth_token`. Authentication tokens are generated using a uniquifier field in the
user's UserModel. If that field is changed (via :meth:`.UserDatastore.set_uniquifier`)
then any existing authentication tokens will no longer be valid. Changing
the user's password will not affect tokens.

Note that prior to release 3.3.0 or if the UserModel doesn't contain the ``fs_uniquifier``
attribute the authentication tokens are generated using the user's password.
Thus if the user changes his or her password their existing authentication token
will become invalid. A new token will need to be retrieved using the user's new
password. Verifying tokens created in this way is very slow.

Two-factor Authentication (experimental)
----------------------------------------
Two-factor authentication is enabled by generating time-based one time passwords
(Tokens). The tokens are generated using the users totp secret, which is unique
per user, and is generated both on first login, and when changing the two-factor
method (Doing this causes the previous totp secret to become invalid). The token
is provided by one of 3 methods - email, sms (service is not provided), or
Google Authenticator. By default, tokens provided by google authenticator are
valid for 2 minutes, tokens sent by mail for up to 5 minute and tokens sent by
sms for up to 2 minutes. The QR code used to supply Google Authenticator with
the secret is generated using the PyQRCode library.
This feature is marked experimental meaning that backwards incompatible changes
might occur during minor releases. While the feature is operational, it has these
known limitations:

    * Limited and incomplete JSON support
    * Incomplete i18n support
    * Not enough documentation to use w/o looking at code

Email Confirmation
------------------

If desired you can require that new users confirm their email address.
Flask-Security will send an email message to any new users with a confirmation
link. Upon navigating to the confirmation link, the user will be automatically
logged in. There is also view for resending a confirmation link to a given email
if the user happens to try to use an expired token or has lost the previous
email. Confirmation links can be configured to expire after a specified amount
of time.


Password Reset/Recovery
-----------------------

Password reset and recovery is available for when a user forgets his or her
password. Flask-Security sends an email to the user with a link to a view which
they can reset their password. Once the password is reset they are automatically
logged in and can use the new password from then on. Password reset links  can
be configured to expire after a specified amount of time.


User Registration
-----------------

Flask-Security comes packaged with a basic user registration view. This view is
very simple and new users need only supply an email address and their password.
This view can be overridden if your registration process requires more fields.


Login Tracking
--------------

Flask-Security can, if configured, keep track of basic login events and
statistics. They include:

* Last login date
* Current login date
* Last login IP address
* Current login IP address
* Total login count


JSON/Ajax Support
-----------------

Flask-Security supports JSON/Ajax requests where appropriate. Please
look at :ref:`csrftopic` for details on how to work with JSON and
Single Page Applications. More specifically
JSON is supported for the following operations:

* Login requests
* Registration requests
* Change password requests
* Confirmation requests
* Forgot password requests
* Passwordless login requests
* Two-factor login requests
* Change two-factor method requests

In addition, Single-Page-Applications (like those built with Vue, Angular, and
React) are supported via customizable redirect links.

Command Line Interface
----------------------

Basic `Click`_ commands for managing users and roles are automatically
registered. They can be completely disabled or their names can be changed.
Run ``flask --help`` and look for users and roles.


.. _Click: https://palletsprojects.com/p/click/
.. _Flask-Login: https://flask-login.readthedocs.org/en/latest/
.. _Flask-WTF: https://flask-wtf.readthedocs.io/en/stable/csrf.html
.. _alternative token: https://flask-login.readthedocs.io/en/latest/#alternative-tokens
.. _Flask-Principal: https://pypi.org/project/Flask-Principal/
.. _documentation on this topic: http://packages.python.org/Flask-Principal/#granular-resource-protection
.. _passlib: https://passlib.readthedocs.io/en/stable/
.. _bcrypt: https://en.wikipedia.org/wiki/Bcrypt
.. _PyQRCode: https://pypi.python.org/pypi/PyQRCode/
