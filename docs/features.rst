Features
========

Flask-Security allows you to quickly add common security mechanisms to your
Flask application. They include:


Session Based Authentication
----------------------------

Session based authentication is fulfilled entirely by the `Flask-Login`_
extension. Flask-Security handles the configuration of Flask-Login automatically
based on a few of its own configuration values and uses Flask-Login's
`alternative token`_ feature to associate the value of ``fs_uniquifier`` with the user.
(This enables easily invalidating all existing sessions for a given user without
having to change their user id). `Flask-WTF`_
integrates with the session as well to provide out of the box CSRF support.
Flask-Security extends that to support configurations that would require CSRF for requests that are
authenticated via session cookies, but not for requests authenticated using tokens.


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
environment. Hash algorithms not listed in ``SECURITY_PASSWORD_SINGLE_HASH``
will be double hashed - first an HMAC will be computed, then the selected hash
function will be used. In this case - you must provide a ``SECURITY_PASSWORD_SALT``.
A good way to generate this is::

    secrets.SystemRandom().getrandbits(128)

Bear in mind passlib does not assume which
algorithm you will choose and may require additional libraries to be installed.

Password Validation and Complexity
-----------------------------------
Consult :ref:`pass_validation_topic`.


Basic HTTP Authentication
-------------------------

Basic HTTP authentication is achievable using a simple view method decorator.
This feature expects the incoming authentication information to identify a user
in the system. This means that the username must be equal to their email address.


Token Authentication
--------------------

Token based authentication can be used by retrieving the user auth token from an
authentication endpoint (e.g. ``/login``, ``/us-signin``).
Perform an HTTP POST with a query param of ``include_auth_token`` and the authentication details
as JSON data.
A successful call will return the authentication token. This token can be used in subsequent
requests to protected resources. The auth token should be supplied in the request
through an HTTP header or query string parameter. By default the HTTP header
name is `Authentication-Token` and the default query string parameter name is
`auth_token`.

Authentication tokens are generated using a uniquifier field in the
user's UserModel. By default that field is ``fs_uniquifier``. This means that
if that field is changed (via :meth:`.UserDatastore.set_uniquifier`)
then any existing authentication tokens will no longer be valid. This value is changed
whenever a user changes their password. If this is not the desired behavior then you can add an additional
attribute to the UserModel: ``fs_token_uniquifier`` and that will be used instead, thus
isolating password changes from authentication tokens. That attribute can be changed via
:meth:`.UserDatastore.set_token_uniquifier`. This attribute should have ``unique=True``.
Unlike ``fs_uniquifier``, it can be set to ``nullable`` - it will automatically be generated
at first use if null.

.. _two-factor:

Two-factor Authentication
----------------------------------------

Two-factor authentication is enabled by generating time-based one time passwords
(Tokens). The tokens are generated using the users `totp secret`_, which is unique
per user, and is generated both on first login, and when changing the two-factor
method (doing this causes the previous totp secret to become invalid). The token
is provided by one of 3 methods - email, sms (service is not provided), or
an authenticator app such as Google Authenticator, LastPass Authenticator, or Authy.
By default, tokens provided by the authenticator app are
valid for 2 minutes, tokens sent by mail for up to 5 minute and tokens sent by
sms for up to 2 minutes. The QR code used to supply the authenticator app with
the secret is generated using the `qrcode <https://pypi.org/project/qrcode/>`_ library.
Please read :ref:`2fa_theory_of_operation` for more details.

The Two-factor feature offers the ability for a user to 'rescue' themselves if
they lose track of their secondary factor device. Rescue options include sending
a one time code via email, send an email to the application admin, and using a previously
generated and downloaded one-time code (see :py:data:`SECURITY_MULTI_FACTOR_RECOVERY_CODES`).

.. _unified-sign-in:

Unified Sign In
---------------
**This feature is in Beta - mostly due to it being brand new and little to no production soak time**

Unified sign in provides a generalized login endpoint that takes an `identity`
and a `passcode`; where (based on configuration):

    * `identity` is any of :py:data:`SECURITY_USER_IDENTITY_ATTRIBUTES` (e.g. email, username, phone)
    * `passcode` is a password or a one-time code (delivered via email, SMS, or authenticator app)

Please see this `Wikipedia`_ article about multi-factor authentication.

Using this feature, it is possible to not require the user to have a stored password
at all, and just require the use of a one-time code. The mechanisms for generating
and delivering the one-time code are similar to common two-factor mechanisms.

This one-time code can be configured to be delivered via email, SMS or authenticator app -
however be aware that NIST does not recommend email for this purpose (though many web sites do so)
due to the fact that a) email may travel through
many different servers as part of being delivered - and b) is available from any device.

Using SMS or an authenticator app means you are providing "something you have" (the mobile device)
and either "something you know" (passcode to unlock your device)
or "something you are" (biometric quality to unlock your device).
This effectively means that using a one-time code to sign in, is in fact already two-factor (if using
SMS or authenticator app). Many large authentication providers already offer this - here is
`Microsoft's`_ version.

Note that by configuring :py:data:`SECURITY_US_ENABLED_METHODS` an application can
use this endpoint JUST with identity/password or in fact disallow passwords altogether.

Unified sign in is integrated with two-factor authentication. Since in general
there is no need for a second factor if the initial authentication was with SMS or
an authenticator application, the :py:data:`SECURITY_US_MFA_REQUIRED` configuration
determines which primary authentication mechanisms require a second factor. By default
limited to ``email`` and ``password`` (if two-factor is enabled).

Be aware that by default, the :py:data:`SECURITY_US_SETUP_URL` endpoint is protected
with a freshness check (see :meth:`flask_security.auth_required`) which means it requires a session
cookie to function properly. This is true even if using JSON payload or token authentication.
If you disable the freshness check then sessions aren't required.

`Current Limited Functionality`:

    * Change password does not work if a user registers without a password. However
      forgot-password will allow the user to set a new password.
    * Registration and Confirmation only work with email - so while you can enable multiple
      authentication methods, you still have to register with email.

.. _webauthn:

WebAuthn
---------------
**This feature is in Beta - mostly due to it being brand new and little to no production soak time**

WebAuthn is a standardized protocol that connects authenticators (such as YubiKey and mobile biometrics)
with websites. Flask-Security supports using WebAuthn keys as either 'first' or 'secondary'
authenticators. Please read :ref:`webauthn_topic` for more details.

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

Password reset and recovery is available for when a user forgets their
password. Flask-Security sends an email to the user with a link to a view which
allows them to reset their password. Once the password is reset they are redirected to
the login page where they need to authenticate using the new password.
Password reset links can be configured to expire after a specified amount of time.

As with password change - this will update the the user's ``fs_uniquifier`` attribute
which will invalidate all existing sessions AND (by default) all authentication tokens.


User Registration
-----------------

Flask-Security comes packaged with a basic user registration view. This view is
very simple and new users need only supply an email address and their password.
This view can be overridden if your registration process requires more fields.
User email is validated and normalized using the
`email_validator <https://pypi.org/project/email-validator/>`_ package.

The :py:data:`SECURITY_USERNAME_ENABLE` configuration option, when set to ``True``, will add
support for the user to register a username in addition to an email. By default, the user will be
able to authenticate with EITHER email or username - however that can be changed via the
:py:data:`SECURITY_USER_IDENTITY_ATTRIBUTES`.

Password Change
---------------
Flask-Security comes packaged with a basic change user password view. Unlike password
recovery, this endpoint is used when the user is already authenticated. The result
of a successful password change is not only a new password, but a new value for ``fs_uniquifier``.
This has the effect is immediately invalidating all existing sessions. The change request
itself effectively re-logs in the user so a new session is created. Note that since the user
is effectively re-logged in, the same signals are sent as when the user normally authenticates.

*NOTE*: The ``fs_uniquifier`` by default, controls both sessions and authenticated tokens.
Thus changing the password also invalidates all authentication tokens. This may not be desirable
behavior, so if the UserModel contains an attribute ``fs_token_uniquifier``, then that will be used
when generating authentication tokens and so won't be affected by password changes.


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
* Unified sign in requests
* Registration requests
* Change password requests
* Confirmation requests
* Forgot password requests
* Passwordless login requests
* Two-factor login requests
* Change two-factor method requests
* WebAuthn registration and signin requests
* Two-Factor recovery code requests

In addition, Single-Page-Applications (like those built with Vue, Angular, and
React) are supported via customizable redirect links.

Note: All registration requests done through JSON/Ajax utilize the ``confirm_register_form``.

Command Line Interface
----------------------

Basic `Click`_ commands for managing users and roles are automatically
registered. They can be completely disabled or their names can be changed.
Run ``flask --help`` and look for users and roles.


Social/Oauth Authentication
----------------------------
Flask-Security provides a thin layer which integrates `authlib`_ with Flask-Security
views and features (such as two-factor authentication). Flask-Security is shipped
with support for github and google - others can be added by the application (see `loginpass`_
for many examples).

See :py:class:`flask_security.OAuthGlue`

Please note - this is for authentication only, and the authenticating user must
already be a registered user in your application. Once authenticated, all further
authorization uses Flask-Security role/permission mechanisms.

See `Flask OAuth Client <https://docs.authlib.org/en/latest/client/flask.html>`_
for details. Note in particular, that you must setup and provide provider specific
information - and most importantly - XX_CLIENT_ID and XX_CLIENT_SECRET should be
specified as environment variables.

A very simple example of configuring social auth with Flask-Security is available
in the `examples` directory.

.. _Click: https://palletsprojects.com/p/click/
.. _Flask-Login: https://flask-login.readthedocs.org/en/latest/
.. _Flask-WTF: https://flask-wtf.readthedocs.io/en/1.0.x/csrf/
.. _alternative token: https://flask-login.readthedocs.io/en/latest/#alternative-tokens
.. _Flask-Principal: https://pypi.org/project/Flask-Principal/
.. _documentation on this topic: http://packages.python.org/Flask-Principal/#granular-resource-protection
.. _passlib: https://passlib.readthedocs.io/en/stable/
.. _totp secret: https://passlib.readthedocs.io/en/stable/narr/totp-tutorial.html#overview
.. _bcrypt: https://en.wikipedia.org/wiki/Bcrypt
.. _PyQRCode: https://pypi.python.org/pypi/PyQRCode/
.. _Wikipedia: https://en.wikipedia.org/wiki/Multi-factor_authentication
.. _Microsoft's: https://docs.microsoft.com/en-us/azure/active-directory/user-help/user-help-auth-app-overview
.. _authlib: https://authlib.org/
.. _loginpass: https://github.com/authlib/loginpass
