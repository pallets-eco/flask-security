Configuration
=============

The following configuration values are used by Flask-Security:

Core
--------------

These configuration keys are used globally across all features.

.. py:data:: SECRET_KEY

    This is actually part of Flask - but is used by Flask-Security to sign all tokens.
    It is critical this is set to a strong value. For python3 consider using: ``secrets.token_urlsafe()``

.. py:data:: SECURITY_BLUEPRINT_NAME

    Specifies the name for the Flask-Security blueprint.

    Default: ``security``.

.. py:data:: SECURITY_URL_PREFIX

    Specifies the URL prefix for the Flask-Security blueprint.

    Default: ``None``.

.. py:data:: SECURITY_SUBDOMAIN

    Specifies the subdomain for the Flask-Security blueprint.

    Default: ``None``.
.. py:data:: SECURITY_FLASH_MESSAGES

    Specifies whether or not to flash messages during security procedures.

    Default: ``True``.
.. py:data:: SECURITY_I18N_DOMAIN

    Specifies the name for domain used for translations.

    Default: ``flask_security``.
.. py:data:: SECURITY_I18N_DIRNAME

    Specifies the directory containing the ``MO`` files used for translations.

    Default: ``[PATH_LIB]/flask_security/translations``.

.. py:data:: SECURITY_PASSWORD_HASH

    Specifies the password hash algorithm to use when hashing passwords.
    Recommended values for production systems are ``bcrypt``, ``argon2``, ``sha512_crypt``, or
    ``pbkdf2_sha512``. Some algorithms require the installation  of a backend package (e.g. `bcrypt`_, `argon2`_).

    Default:``bcrypt``.

.. py:data:: SECURITY_PASSWORD_SCHEMES

    List of support password hash algorithms. ``SECURITY_PASSWORD_HASH``
    must be from this list. Passwords encrypted with any of these schemes will be honored.

.. py:data:: SECURITY_DEPRECATED_PASSWORD_SCHEMES

    List of password hash algorithms that are considered weak and
    will be accepted, however on first use, will be re-hashed to the current
    setting of ``SECURITY_PASSWORD_HASH``.

    Default: ``["auto"]`` which means any password found that wasn't
    hashed using ``SECURITY_PASSWORD_HASH`` will be re-hashed.

.. py:data:: SECURITY_PASSWORD_SALT

    Specifies the HMAC salt. This is required for all schemes that
    are configured for double hashing. A good salt can be generated using:
    ``secrets.SystemRandom().getrandbits(128)``.

    Default: ``None``.

.. py:data:: SECURITY_PASSWORD_SINGLE_HASH

    A list of schemes that should not be hashed twice. By default, passwords are
    hashed twice, first with ``SECURITY_PASSWORD_SALT``, and then with a random salt.

    Default: a list of known schemes not working with double hashing (`django_{digest}`, `plaintext`).

.. py:data:: SECURITY_HASHING_SCHEMES

    List of algorithms used for encrypting/hashing sensitive data within a token
    (Such as is sent with confirmation or reset password).

    Default: ``sha256_crypt``.
.. py:data:: SECURITY_DEPRECATED_HASHING_SCHEMES

    List of deprecated algorithms used for creating and validating tokens.

    Default: ``hex_md5``.

.. py:data:: SECURITY_PASSWORD_HASH_OPTIONS

    Specifies additional options to be passed to the hashing method. This is deprecated as of passlib 1.7.

.. py:data:: SECURITY_PASSWORD_HASH_PASSLIB_OPTIONS

    Pass additional options to the various hashing methods. This is a
    dict of the form ``{<scheme>__<option>: <value>, ..}``
    e.g. {"argon2__rounds": 10}.

    .. versionadded:: 3.3.1

.. py:data:: SECURITY_TOKEN_AUTHENTICATION_KEY

    Specifies the query string parameter to read when using token authentication.

    Default: ``auth_token``.

.. py:data:: SECURITY_TOKEN_AUTHENTICATION_HEADER

    Specifies the HTTP header to read when using token authentication.

    Default: ``Authentication-Token``.

.. py:data:: SECURITY_TOKEN_MAX_AGE

    Specifies the number of seconds before an authentication token expires.

    Default: ``None``, meaning the token never expires.

.. py:data:: SECURITY_DEFAULT_HTTP_AUTH_REALM

    Specifies the default authentication realm when using basic HTTP auth.

    Default: ``Login Required``

.. py:data:: SECURITY_USE_VERIFY_PASSWORD_CACHE

    If ``True`` enables cache for token verification, which speeds up further
    calls to authenticated routes using authentication-token and slow hash algorithms (like bcrypt).
    If you set this - you must ensure that `cachetools`_ is installed.
    **Note: this will likely be deprecated and removed in 4.0. It**
    **has known limitations, and there is now a better/faster way to**
    **generate and verify auth tokens.**

    Default: ``None``.

.. py:data:: SECURITY_VERIFY_HASH_CACHE_MAX_SIZE

    Limitation for token validation cache size. Rules are the ones of TTLCache of
    cachetools package.

    Default: ``500``

.. py:data:: SECURITY_VERIFY_HASH_CACHE_TTL

    Time to live for password check cache entries.

    Default: ``300`` (5 minutes)

.. py:data:: SECURITY_REDIRECT_BEHAVIOR

    Passwordless login, confirmation, and reset password have GET endpoints that validate
    the passed token and redirect to an action form.
    For Single-Page-Applications style UIs which need to control their own internal URL routing these redirects
    need to not contain forms, but contain relevant information as query parameters.
    Setting this to ``spa`` will enable that behavior.

    Default: ``None`` which is existing html-style form redirects.

    .. versionadded:: 3.3.0

.. py:data:: SECURITY_REDIRECT_HOST

    Mostly for development purposes, the UI is often developed
    separately and is running on a different port than the
    Flask application. In order to test redirects, the `netloc`
    of the redirect URL needs to be rewritten. Setting this to e.g. `localhost:8080` does that.

    Default: ``None``.

    .. versionadded:: 3.3.0

.. py:data:: SECURITY_CSRF_PROTECT_MECHANISMS

    Authentication mechanisms that require CSRF protection.
    These are the same mechanisms as are permitted in the ``@auth_required`` decorator.

    Default: ``("basic", "session", "token")``.

.. py:data:: SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS

    If ``True`` then CSRF will not be required for endpoints
    that don't require authentication (e.g. login, logout, register, forgot_password).

    Default: ``False``.

.. py:data:: SECURITY_CSRF_COOKIE

    A dict that defines the parameters required to
    set a CSRF cookie. At a minimum it requires a 'key'.
    The complete set of parameters is described in Flask's `set_cookie`_ documentation.

    Default: ``{"key": None}`` which means no cookie will sent.

.. py:data:: SECURITY_CSRF_HEADER

    The HTTP Header name that will contain the CSRF token. ``X-XSRF-Token``
    is used by packages such as `axios`_.

    Default: ``X-XSRF-Token``.

.. py:data:: SECURITY_CSRF_COOKIE_REFRESH_EACH_REQUEST

    By default, csrf_tokens have an expiration (controlled
    by the configuration variable ``WTF_CSRF_TIME_LIMIT``.
    This can cause CSRF failures if say an application is left
    idle for a long time. You can set that time limit to ``None``
    or have the CSRF cookie sent on every request (which will give
    it a new expiration time).

    Default: ``False``.

.. py:data:: SECURITY_EMAIL_SENDER

    Specifies the email address to send emails as.

    Default: value set to ``MAIL_DEFAULT_SENDER`` if Flask-Mail is used otherwise ``no-reply@localhost``.

.. py:data:: SECURITY_USER_IDENTITY_ATTRIBUTES

    Specifies which attributes of the user object can be used for login.

    Default: ``['email']``.

.. py:data:: SECURITY_DEFAULT_REMEMBER_ME

    Specifies the default "remember me" value used when logging in a user.

    Default: ``False``.

.. py:data:: SECURITY_BACKWARDS_COMPAT_UNAUTHN

    If set to ``True`` then the default behavior for authentication
    failures from one of Flask-Security's decorators will be restored to
    be compatible with releases prior to 3.3.0 (return 401 and some static html).

    Default: ``False``.

.. py:data:: SECURITY_BACKWARDS_COMPAT_AUTH_TOKEN

    If set to ``True`` then an Authentication-Token will be returned
    on every successful call to login, reset-password, change-password
    as part of the JSON response. This was the default prior to release 3.3.0
    - however sending Authentication-Tokens (which by default don't expire)
    to session based UIs is a bad security practice.

    Default: ``False``.

.. py:data:: SECURITY_BACKWARDS_COMPAT_AUTH_TOKEN_INVALIDATE

    When ``True`` changing the user's password will also change the user's
    ``fs_uniquifier`` (if it exists) such that existing authentication tokens
    will be rendered invalid.  This restores pre 3.3.0 behavior.

Core - rarely need changing
----------------------------

.. py:data:: SECURITY_DATETIME_FACTORY

    Specifies the default datetime factory.

    Default:``datetime.datetime.utcnow``.

.. py:data:: SECURITY_CONFIRM_SALT

    Specifies the salt value when generating confirmation links/tokens.

    Default: ``"confirm-salt"``.

.. py:data:: SECURITY_RESET_SALT

    Specifies the salt value when generating password reset links/tokens.

    Default: ``"reset-salt"``.

.. py:data:: SECURITY_LOGIN_SALT

    Specifies the salt value when generating login links/tokens.

    Default: ``"login-salt"``.

.. py:data:: SECURITY_REMEMBER_SALT

    Specifies the salt value when generating remember tokens.
    Remember tokens are used instead of user ID's as it is more secure.

    Default: ``"remember-salt"``.

.. py:data:: SECURITY_EMAIL_PLAINTEXT

    Sends email as plaintext using ``*.txt`` template.

    Default: ``True``.

.. py:data:: SECURITY_EMAIL_HTML

    Sends email as HTML using ``*.html`` template.

    Default: ``True``.

.. py:data:: SECURITY_CLI_USERS_NAME

    Specifies the name for the command managing users. Disable by setting ``False``.

    Default: ``users``.

.. py:data:: SECURITY_CLI_ROLES_NAME

    Specifies the name for the command managing roles. Disable by setting ``False``.

    Default: ``roles``.

.. _Totp: https://passlib.readthedocs.io/en/stable/narr/totp-tutorial.html#totp-encryption-setup
.. _set_cookie: https://flask.palletsprojects.com/en/1.1.x/api/?highlight=set_cookie#flask.Response.set_cookie
.. _axios: https://github.com/axios/axios
.. _cachetools: https://pypi.org/project/cachetools/
.. _bcrypt: https://pypi.org/project/bcrypt/
.. _argon2: https://pypi.org/project/argon2-cffi/

Login/Logout
------------
.. py:data:: SECURITY_LOGIN_URL

    Specifies the login URL.

    Default: ``"/login"``.

.. py:data:: SECURITY_LOGOUT_URL

    Specifies the logout URL.

    Default:``"/logout"``.


.. py:data:: SECURITY_POST_LOGIN_VIEW

    Specifies the default view to redirect to after a user logs in. This value can be set to a URL
    or an endpoint name.

    Default: ``"/"``.

.. py:data:: SECURITY_POST_LOGOUT_VIEW

    Specifies the default view to redirect to after a user logs out.
    This value can be set to a URL or an endpoint name.

    Default: ``"/"``.


.. py:data:: SECURITY_UNAUTHORIZED_VIEW

    Specifies the view to redirect to if a user attempts to access a URL/endpoint that they do
    not have permission to access. If this value is ``None``, the user is presented with a default
    HTTP 403 response.

    Default: ``None``.

.. py:data:: SECURITY_LOGIN_USER_TEMPLATE

    Specifies the path to the template for the user login page.

    Default:``security/login_user.html``.

Registerable
------------
.. py:data:: SECURITY_REGISTERABLE

    Specifies if Flask-Security should create a user registration endpoint.

    Default: ``False``

.. py:data:: SECURITY_SEND_REGISTER_EMAIL

    Specifies whether registration email is sent.

    Default: ``True``.
.. py:data:: SECURITY_EMAIL_SUBJECT_REGISTER

    Sets the subject for the confirmation email.

    Default: ``Welcome``.
.. py:data:: SECURITY_REGISTER_USER_TEMPLATE

    Specifies the path to the template for the user registration page.

    Default: ``security/register_user.html``.
.. py:data:: SECURITY_POST_REGISTER_VIEW

    Specifies the view to redirect to after a user successfully registers.
    This value can be set to a URL or an endpoint name. If this value is
    ``None``, the user is redirected to the value of ``SECURITY_POST_LOGIN_VIEW``.

    Default: ``None``.
.. py:data:: SECURITY_REGISTER_URL

    Specifies the register URL.

    Default: ``"/register"``.

Confirmable
-----------

.. py:data:: SECURITY_CONFIRMABLE

    Specifies if users are required to confirm their email address when
    registering a new account. If this value is `True`, Flask-Security creates an endpoint to handle
    confirmations and requests to resend confirmation instructions.

    Default: ``False``.
.. py:data:: SECURITY_CONFIRM_EMAIL_WITHIN

    Specifies the amount of time a user has before their confirmation
    link expires. Always pluralize the time unit for this value.

    Default: ``5 days``.
.. py:data:: SECURITY_CONFIRM_URL

    Specifies the email confirmation URL.

    Default: ``"/confirm"``.
.. py:data:: SECURITY_SEND_CONFIRMATION_TEMPLATE

    Specifies the path to the template for the resend confirmation instructions page.

    Default: ``security/send_confirmation.html``.
.. py:data:: SECURITY_EMAIL_SUBJECT_CONFIRM

    Sets the subject for the email confirmation message.

    Default: ``Please confirm your email``.
.. py:data:: SECURITY_CONFIRM_ERROR_VIEW

    Specifies the view to redirect to if a confirmation error occurs.
    This value can be set to a URL or an endpoint name.
    If this value is ``None``, the user is presented the default view
    to resend a confirmation link. In the case of ``SECURITY_REDIRECT_BEHAVIOR`` == ``spa``
    query params in the redirect will contain the error.

    Default: ``None``.
.. py:data:: SECURITY_POST_CONFIRM_VIEW

    Specifies the view to redirect to after a user successfully confirms their email.
    This value can be set to a URL or an endpoint name. If this value is ``None``, the user is redirected to the
    value of ``SECURITY_POST_LOGIN_VIEW``.

    Default: ``None``.
.. py:data:: SECURITY_AUTO_LOGIN_AFTER_CONFIRM

    If ``False`` then on confirmation  the user will be required to login again.
    Note that the confirmation token is not valid after being used once.
    If ``True``, then the user corresponding to the
    confirmation token will be automatically logged in.

    Default: ``True``.
.. py:data:: SECURITY_LOGIN_WITHOUT_CONFIRMATION

    Specifies if a user may login before confirming their email when
    the value of ``SECURITY_CONFIRMABLE`` is set to ``True``.

    Default:``False``.

Changeable
----------
Configuration variables for the ``SECURITY_CHANGEABLE`` feature:

.. py:data:: SECURITY_CHANGEABLE

    Specifies if Flask-Security should enable the change password endpoint.

    Default: ``False``.
.. py:data:: SECURITY_CHANGE_URL

    Specifies the password change URL.

    Default: ``"/change"``.
.. py:data:: SECURITY_POST_CHANGE_VIEW

    Specifies the view to redirect to after a user successfully changes their password.
    This value can be set to a URL or an endpoint name.
    If this value is ``None``, the user is redirected  to the
    value of ``SECURITY_POST_LOGIN_VIEW``.

    Default: ``None``.
.. py:data:: SECURITY_CHANGE_PASSWORD_TEMPLATE

    Specifies the path to the template for the change password page.

    Default: ``security/change_password.html``.

.. py:data:: SECURITY_SEND_PASSWORD_CHANGE_EMAIL

    Specifies whether password change email is sent.

    Default: ``True``.

.. py:data:: SECURITY_EMAIL_SUBJECT_PASSWORD_CHANGE_NOTICE

    Sets the subject for the password change notice.

    Default: ``Your password has been changed``.

Recoverable
-----------

.. py:data:: SECURITY_RECOVERABLE

    Specifies if Flask-Security should create a password reset/recover endpoint.

    Default: ``False``.

.. py:data:: SECURITY_RESET_URL

    Specifies the password reset URL.

    Default: ``"/reset"``.

.. py:data:: SECURITY_RESET_PASSWORD_TEMPLATE

    Specifies the path to the template for the reset password page.

    Default: ``security/reset_password.html``.

.. py:data:: SECURITY_FORGOT_PASSWORD_TEMPLATE

    Specifies the path to the template for the forgot password page.

    Default: ``security/forgot_password.html``.

.. py:data:: SECURITY_POST_RESET_VIEW

    Specifies the view to redirect to after a user successfully resets their password.
    This value can be set to a URL or an endpoint name. If this
    value is ``None``, the user is redirected  to the value of ``SECURITY_POST_LOGIN_VIEW``.

    Default: ``None``.

.. py:data:: SECURITY_RESET_VIEW

    Specifies the view/URL to redirect to after a GET reset-password link.
    This is only valid if ``SECURITY_REDIRECT_BEHAVIOR`` == ``spa``.
    Query params in the redirect will contain the ``token`` and ``email``.

    Default: ``None``.

.. py:data:: SECURITY_RESET_ERROR_VIEW

    Specifies the view/URL to redirect to after a GET reset-password link when there is an error.
    This is only valid if ``SECURITY_REDIRECT_BEHAVIOR`` == ``spa``.
    Query params in the redirect will contain the error.

    Default: ``None``.

.. py:data:: SECURITY_RESET_PASSWORD_WITHIN

    Specifies the amount of time a user has before their password reset link expires.
    Always pluralize the time unit for this value.

    Default: ``5 days``.

.. py:data:: SECURITY_SEND_PASSWORD_RESET_EMAIL

    Specifies whether password reset email is sent. These are instructions
    including a link that can be clicked on.

    Default: ``True``.

.. py:data:: SECURITY_SEND_PASSWORD_RESET_NOTICE_EMAIL

    Specifies whether password reset notice email is sent. This is sent once
    a user's password was successfully reset.

    Default: ``True``.

.. py:data:: SECURITY_EMAIL_SUBJECT_PASSWORD_RESET

    Sets the subject for the password reset email.

    Default: ``Password reset instructions``.

.. py:data:: SECURITY_EMAIL_SUBJECT_PASSWORD_NOTICE

    Sets subject for the password notice.

    Default: ``Your password has been reset``.

Two-Factor
-----------
Configuration related to the two-factor authentication feature.

.. versionadded:: 3.2.0

.. py:data:: SECURITY_TWO_FACTOR

    Specifies if Flask-Security should enable the two-factor login feature.
    If set to ``True``, in addition to their passwords, users will be required to
    enter a code that is sent to them. Note that unless
    ``SECURITY_TWO_FACTOR_REQUIRED`` is set - this is opt-in.

    Default: ``False``.
.. py:data:: SECURITY_TWO_FACTOR_REQUIRED

    If set to ``True`` then all users will be required to setup and use two factor authorization.

    Default: ``False``.
.. py:data:: SECURITY_TWO_FACTOR_ENABLED_METHODS

    Specifies the default enabled methods for two-factor authentication.

    Default: ``['mail', 'authenticator', 'sms']`` which are the only currently supported methods.
.. py:data:: SECURITY_TWO_FACTOR_URI_SERVICE_NAME

    Specifies the name of the service or application that the user is authenticating to.

    Default: ``service_name``.

    .. deprecated:: 3.4.0 see: SECURITY_TOTP_ISSUER
.. py:data:: SECURITY_TWO_FACTOR_SMS_SERVICE

    Specifies the name of the sms service provider.

    Default: ``Dummy`` which does nothing.

    .. deprecated:: 3.4.0 see: SECURITY_SMS_SERVICE

.. py:data:: SECURITY_TWO_FACTOR_SMS_SERVICE_CONFIG

    Specifies a dictionary of basic configurations needed for use of a sms service.

    Default: ``{'ACCOUNT_ID': NONE, 'AUTH_TOKEN':NONE, 'PHONE_NUMBER': NONE}``

    .. deprecated:: 3.4.0 see: SECURITY_SMS_SERVICE_CONFIG

.. py:data:: SECURITY_TWO_FACTOR_AUTHENTICATOR_VALIDITY

    Specifies the number of seconds access token is valid.

    Default: ``2 minutes``.
.. py:data:: SECURITY_TWO_FACTOR_MAIL_VALIDITY

    Specifies the number of seconds access token is valid.

    Default: ``5 minutes``.
.. py:data:: SECURITY_TWO_FACTOR_SMS_VALIDITY

    Specifies the number of seconds access token is valid.

    Default: ``2 minutes``.
.. py:data:: SECURITY_TWO_FACTOR_RESCUE_MAIL

    Specifies the email address users send mail to when they can't complete the
    two-factor authentication login.

    Default: ``no-reply@localhost``.

.. py:data:: SECURITY_TWO_FACTOR_SECRET

    Secret used to encrypt totp_password both into DB and in session cookie.
    Best practice is to set this to:

    .. code-block:: python

        "{1: passlib.totp.generate_secret()}"

    See: `Totp`_ for details.

    .. deprecated:: 3.4.0 see: SECURITY_TOTP_SECRETS

.. py:data:: SECURITY_EMAIL_SUBJECT_TWO_FACTOR

    Sets the subject for the two factor feature.

    Default: ``Two-factor Login``
.. py:data:: SECURITY_EMAIL_SUBJECT_TWO_FACTOR_RESCUE

    Sets the subject for the two factor help function.

    Default: ``Two-factor Rescue``
.. py:data:: SECURITY_TWO_FACTOR_VERIFY_CODE_TEMPLATE

    Specifies the path to the template for the verify code page for the two-factor authentication process.

    Default: ``security/two_factor_verify_code.html``.
.. py:data:: SECURITY_TWO_FACTOR_SETUP_TEMPLATE

    Specifies the path to the template for the setup page for the two factor authentication process.

    Default: ``security/two_factor_setup.html``.
.. py:data:: SECURITY_TWO_FACTOR_VERIFY_PASSWORD_TEMPLATE

    Specifies the path to the template for the change method page for the two
    factor authentication process.

    Default: ``security/two_factor_verify_password.html``.

.. py:data:: SECURITY_TWO_FACTOR_SETUP_URL

    Specifies the two factor setup URL.

    Default: ``"/tf-setup"``.
.. py:data:: SECURITY_TWO_FACTOR_TOKEN_VALIDATION_URL

    Specifies the two factor token validation URL.

    Default: ``"/tf-validate"``.
.. py:data:: SECURITY_TWO_FACTOR_QRCODE_URL

    Specifies the two factor request QrCode URL.

    Default: ``/tf-qrcode``.
.. py:data:: SECURITY_TWO_FACTOR_RESCUE_URL

    Specifies the two factor rescue URL.

    Default: ``"/tf-rescue"``.
.. py:data:: SECURITY_TWO_FACTOR_CONFIRM_URL

    Specifies the two factor password confirmation URL.

    Default: ``"/tf-confirm"``.

Passwordless
-------------

.. py:data:: SECURITY_PASSWORDLESS

    Specifies if Flask-Security should enable the passwordless login feature.
    If set to ``True``, users are not required to enter a password to login but are
    sent an email with a login link.
    **This feature is being replaced with a more generalized passwordless feature
    that includes using SMS or authenticator applications for generating codes.**

    Default: ``False``.

.. py:data:: SECURITY_SEND_LOGIN_TEMPLATE

    Specifies the path to the template for the send login instructions page for
    passwordless logins.

    Default:``security/send_login.html``.

.. py:data:: SECURITY_EMAIL_SUBJECT_PASSWORDLESS

    Sets the subject for the passwordless feature.

    Default: ``Login instructions``.

.. py:data:: SECURITY_LOGIN_WITHIN

    Specifies the amount of time a user has before a login link expires.
    Always pluralize the time unit for this value.

    Default: ``1 days``.

.. py:data:: SECURITY_LOGIN_ERROR_VIEW

    Specifies the view/URL to redirect to after a GET passwordless link when there is an error.
    This is only valid if ``SECURITY_REDIRECT_BEHAVIOR`` == ``spa``.
    Query params in the redirect will contain the error.

    Default: ``None``.

Trackable
----------
.. py:data:: SECURITY_TRACKABLE

    Specifies if Flask-Security should track basic user login statistics. If set to ``True``, ensure your
    models have the required fields/attributes and make sure to commit changes after calling
    ``login_user``. Be sure to use `ProxyFix <http://flask.pocoo.org/docs/0.10/deploying/wsgi-standalone/#proxy-setups>`_ if you are using a proxy.

    Default: ``False``

Feature Flags
-------------
All feature flags. By default all are 'False'/not enabled.

* ``SECURITY_CONFIRMABLE``
* ``SECURITY_REGISTERABLE``
* ``SECURITY_RECOVERABLE``
* ``SECURITY_TRACKABLE``
* ``SECURITY_PASSWORDLESS``
* ``SECURITY_CHANGEABLE``
* ``SECURITY_TWO_FACTOR``

URLs and Views
--------------
A list of all URLs and Views:

* ``SECURITY_LOGIN_URL``
* ``SECURITY_LOGOUT_URL``
* ``SECURITY_REGISTER_URL``
* ``SECURITY_RESET_URL``
* ``SECURITY_CHANGE_URL``
* ``SECURITY_CONFIRM_URL``
* ``SECURITY_TWO_FACTOR_SETUP_URL``
* ``SECURITY_TWO_FACTOR_TOKEN_VALIDATION_URL``
* ``SECURITY_TWO_FACTOR_QRCODE_URL``
* ``SECURITY_TWO_FACTOR_RESCUE_URL``
* ``SECURITY_TWO_FACTOR_CONFIRM_URL``
* ``SECURITY_POST_LOGIN_VIEW``
* ``SECURITY_POST_LOGOUT_VIEW``
* ``SECURITY_CONFIRM_ERROR_VIEW``
* ``SECURITY_POST_REGISTER_VIEW``
* ``SECURITY_POST_CONFIRM_VIEW``
* ``SECURITY_POST_RESET_VIEW``
* ``SECURITY_POST_CHANGE_VIEW``
* ``SECURITY_UNAUTHORIZED_VIEW``
* ``SECURITY_RESET_VIEW``
* ``SECURITY_RESET_ERROR_VIEW``
* ``SECURITY_LOGIN_ERROR_VIEW``

Template Paths
--------------
A list of all templates:

* ``SECURITY_FORGOT_PASSWORD_TEMPLATE``
* ``SECURITY_LOGIN_USER_TEMPLATE``
* ``SECURITY_REGISTER_USER_TEMPLATE``
* ``SECURITY_RESET_PASSWORD_TEMPLATE``
* ``SECURITY_CHANGE_PASSWORD_TEMPLATE``
* ``SECURITY_SEND_CONFIRMATION_TEMPLATE``
* ``SECURITY_SEND_LOGIN_TEMPLATE``
* ``SECURITY_TWO_FACTOR_VERIFY_CODE_TEMPLATE``
* ``SECURITY_TWO_FACTOR_SETUP_TEMPLATE``
* ``SECURITY_TWO_FACTOR_VERIFY_PASSWORD_TEMPLATE``

Messages
-------------

The following are the messages Flask-Security uses.  They are tuples; the first
element is the message and the second element is the error level.

The default messages and error levels can be found in ``core.py``.

* ``SECURITY_MSG_ALREADY_CONFIRMED``
* ``SECURITY_MSG_ANONYMOUS_USER_REQUIRED``
* ``SECURITY_MSG_CONFIRMATION_EXPIRED``
* ``SECURITY_MSG_CONFIRMATION_REQUEST``
* ``SECURITY_MSG_CONFIRMATION_REQUIRED``
* ``SECURITY_MSG_CONFIRM_REGISTRATION``
* ``SECURITY_MSG_DISABLED_ACCOUNT``
* ``SECURITY_MSG_EMAIL_ALREADY_ASSOCIATED``
* ``SECURITY_MSG_EMAIL_CONFIRMED``
* ``SECURITY_MSG_EMAIL_NOT_PROVIDED``
* ``SECURITY_MSG_FORGOT_PASSWORD``
* ``SECURITY_MSG_INVALID_CONFIRMATION_TOKEN``
* ``SECURITY_MSG_INVALID_EMAIL_ADDRESS``
* ``SECURITY_MSG_INVALID_LOGIN_TOKEN``
* ``SECURITY_MSG_INVALID_PASSWORD``
* ``SECURITY_MSG_INVALID_REDIRECT``
* ``SECURITY_MSG_INVALID_RESET_PASSWORD_TOKEN``
* ``SECURITY_MSG_LOGIN``
* ``SECURITY_MSG_LOGIN_EMAIL_SENT``
* ``SECURITY_MSG_LOGIN_EXPIRED``
* ``SECURITY_MSG_PASSWORDLESS_LOGIN_SUCCESSFUL``
* ``SECURITY_MSG_PASSWORD_CHANGE``
* ``SECURITY_MSG_PASSWORD_INVALID_LENGTH``
* ``SECURITY_MSG_PASSWORD_IS_THE_SAME``
* ``SECURITY_MSG_PASSWORD_MISMATCH``
* ``SECURITY_MSG_PASSWORD_NOT_PROVIDED``
* ``SECURITY_MSG_PASSWORD_NOT_SET``
* ``SECURITY_MSG_PASSWORD_RESET``
* ``SECURITY_MSG_PASSWORD_RESET_EXPIRED``
* ``SECURITY_MSG_PASSWORD_RESET_REQUEST``
* ``SECURITY_MSG_REFRESH``
* ``SECURITY_MSG_RETYPE_PASSWORD_MISMATCH``
* ``SECURITY_MSG_TWO_FACTOR_INVALID_TOKEN``
* ``SECURITY_MSG_TWO_FACTOR_LOGIN_SUCCESSFUL``
* ``SECURITY_MSG_TWO_FACTOR_CHANGE_METHOD_SUCCESSFUL``
* ``SECURITY_MSG_TWO_FACTOR_PASSWORD_CONFIRMATION_DONE``
* ``SECURITY_MSG_TWO_FACTOR_PASSWORD_CONFIRMATION_NEEDED``
* ``SECURITY_MSG_TWO_FACTOR_PERMISSION_DENIED``
* ``SECURITY_MSG_TWO_FACTOR_METHOD_NOT_AVAILABLE``
* ``SECURITY_MSG_TWO_FACTOR_DISABLED``
* ``SECURITY_MSG_UNAUTHORIZED``
* ``SECURITY_MSG_UNAUTHENTICATED``
* ``SECURITY_MSG_USER_DOES_NOT_EXIST``
