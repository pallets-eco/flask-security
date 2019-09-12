Configuration
=============

The following configuration values are used by Flask-Security:

Core
--------------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

==============================================   =============================================
``SECRET_KEY``                                   This is actually part of Flask - but is used by
                                                 Flask-Security to sign all tokens.
                                                 It is critical this is set to a strong value. For python3
                                                 consider using: ``secrets.token_urlsafe()``
``SECURITY_BLUEPRINT_NAME``                      Specifies the name for the
                                                 Flask-Security blueprint. Defaults to
                                                 ``security``.
``SECURITY_CLI_USERS_NAME``                      Specifies the name for the command
                                                 managing users. Disable by setting
                                                 ``False``. Defaults to ``users``.
``SECURITY_CLI_ROLES_NAME``                      Specifies the name for the command
                                                 managing roles. Disable by setting
                                                 ``False``. Defaults to ``roles``.
``SECURITY_URL_PREFIX``                          Specifies the URL prefix for the
                                                 Flask-Security blueprint. Defaults to
                                                 ``None``.
``SECURITY_SUBDOMAIN``                           Specifies the subdomain for the
                                                 Flask-Security blueprint. Defaults to
                                                 ``None``.
``SECURITY_FLASH_MESSAGES``                      Specifies whether or not to flash
                                                 messages during security procedures.
                                                 Defaults to ``True``.
``SECURITY_I18N_DOMAIN``                         Specifies the name for domain
                                                 used for translations.
                                                 Defaults to ``flask_security``.
``SECURITY_I18N_DIRNAME``                        Specifies the directory containing the
                                                 ``MO`` files used for translations.
                                                 Defaults to
                                                 ``[PATH_LIB]/flask_security/translations``.
``SECURITY_PASSWORD_HASH``                       Specifies the password hash algorithm to
                                                 use when hashing passwords. Recommended
                                                 values for production systems are
                                                 ``bcrypt``, ``sha512_crypt``, or
                                                 ``pbkdf2_sha512``. Defaults to
                                                 ``bcrypt``.
``SECURITY_PASSWORD_SCHEMES``                    List of support password hash algorithms.
                                                 ``SECURITY_PASSWORD_HASH`` must be from this list.
                                                 Passwords encrypted with any of these schemes will be honored.
``SECURITY_DEPRECATED_PASSWORD_SCHEMES``         List of password hash algorithms that are considered weak and
                                                 will be accepted, however on first use, will be re-hashed
                                                 to the current default ``SECURITY_PASSWORD_HASH``.
                                                 Default is ``["auto"]`` which means any password found that wasn't
                                                 hashed using ``SECURITY_PASSWORD_HASH`` will be re-hashed.
``SECURITY_PASSWORD_SALT``                       Specifies the HMAC salt. Defaults to
                                                 ``None``.
``SECURITY_PASSWORD_SINGLE_HASH``                A list of schemes that should not be hashed
                                                 twice. By default, passwords are
                                                 hashed twice, first with
                                                 ``SECURITY_PASSWORD_SALT``, and then
                                                 with a random salt.
                                                 Defaults to a list of known schemes
                                                 not working with double hashing
                                                 (`django_{digest}`, `plaintext`).
``SECURITY_HASHING_SCHEMES``                     List of algorithms used for
                                                 encrypting/hashing sensitive data within a token
                                                 (Such as is sent with confirmation or reset password).
                                                 Defaults to ``sha256_crypt``.
``SECURITY_DEPRECATED_HASHING_SCHEMES``          List of deprecated algorithms used for
                                                 creating and validating tokens.
                                                 Defaults to ``hex_md5``.
``SECURITY_PASSWORD_HASH_OPTIONS``               Specifies additional options to be passed
                                                 to the hashing method.
``SECURITY_EMAIL_SENDER``                        Specifies the email address to send
                                                 emails as. Defaults to value set
                                                 to ``MAIL_DEFAULT_SENDER`` if
                                                 Flask-Mail is used otherwise
                                                 ``no-reply@localhost``.
``SECURITY_TWO_FACTOR_RESCUE_MAIL``              Specifies the email address users send
                                                 mail to when they can't complete the
                                                 two-factor authentication login.
                                                 Defaults to ``no-reply@localhost``.
``SECURITY_TWO_FACTOR_SECRET``                   Secret used to encrypt totp_password both into DB
                                                 and in session cookie. Best practice is to set this
                                                 to '{1: passlib.totp.generate_secret()}'.
                                                 See: `Totp`_ for details.
``SECURITY_TOKEN_AUTHENTICATION_KEY``            Specifies the query string parameter to
                                                 read when using token authentication.
                                                 Defaults to ``auth_token``.
``SECURITY_TOKEN_AUTHENTICATION_HEADER``         Specifies the HTTP header to read when
                                                 using token authentication. Defaults to
                                                 ``Authentication-Token``.
``SECURITY_TOKEN_MAX_AGE``                       Specifies the number of seconds before
                                                 an authentication token expires.
                                                 Defaults to None, meaning the token
                                                 never expires.
``SECURITY_DEFAULT_HTTP_AUTH_REALM``             Specifies the default authentication
                                                 realm when using basic HTTP auth.
                                                 Defaults to ``Login Required``
``SECURITY_USE_VERIFY_PASSWORD_CACHE``           If ``True`` Enables cache for token
                                                 verification, which speeds up further
                                                 calls to authenticated routes using
                                                 authentication-token and slow hash algorithms
                                                 (like bcrypt). Defaults to ``None``.
                                                 If you set this - you must ensure that `cachetools`_ is installed.
                                                 **Note: this will likely be deprecated and removed in 4.0. It**
                                                 **has known limitations, and there is now a better/faster way to**
                                                 **generate and verify auth tokens.**
``SECURITY_VERIFY_HASH_CACHE_MAX_SIZE``          Limitation for token validation cache size
                                                 Rules are the ones of TTLCache of
                                                 cachetools package. Defaults to
                                                 ``500``
``SECURITY_VERIFY_HASH_CACHE_TTL``               Time to live for password check cache entries.
                                                 Defaults to ``300`` (5 minutes)
``SECURITY_REDIRECT_BEHAVIOR``                   Passwordless login, confirmation, and
                                                 reset password have GET endpoints that validate
                                                 the passed token and redirect to an action form.
                                                 For Single-Page-Applications style UIs which need
                                                 to control their own internal URL routing these redirects
                                                 need to not contain forms, but contain relevant information
                                                 as query parameters. Setting this to ``spa`` will enable
                                                 that behavior. Defaults to ``None`` which is existing
                                                 html-style form redirects.
``SECURITY_REDIRECT_HOST``                       Mostly for development purposes, the UI is often developed
                                                 separately and is running on a different port than the
                                                 Flask application. In order to test redirects, the `netloc`
                                                 of the redirect URL needs to be rewritten. Setting this
                                                 to e.g. `localhost:8080` does that. Defaults to ``None``
``SECURITY_CSRF_PROTECT_MECHANISMS``             Authentication mechanisms that require CSRF protection.
                                                 These are the same mechanisms as are permitted
                                                 in the ``@auth_required`` decorator.
                                                 Defaults to ``("basic", "session", "token")``
``SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS``        If ``True`` then CSRF will not be required for endpoints
                                                 that don't require authentication
                                                 (e.g. login, logout, register, forgot_password).
                                                 Defaults to ``False``
``SECURITY_CSRF_COOKIE``                         A dict that defines the parameters required to
                                                 set a CSRF cookie. At a minimum it requires a 'key'.
                                                 The complete set of parameters is described in Flask's
                                                 `set_cookie`_ documentation.
                                                 Defaults to ``{"key": None}`` whic means no cookie will
                                                 sent.
``SECURITY_CSRF_HEADER``                         The HTTP Header name that will contain the CSRF token.
                                                 ``X-XSRF-Token`` is used by packages such as `axios`_.
                                                 Defaults to ``X-XSRF-Token``.
``SECURITY_CSRF_COOKIE_REFRESH_EACH_REQUEST``    By default, csrf_tokens have an expiration (controlled
                                                 the the configuration variable ``WTF_CSRF_TIME_LIMIT``.
                                                 This can cause CSRF failures if say an application is left
                                                 idle for a long time. You can set that time limit to ``None``
                                                 or have the CSRF cookie sent on every request (which will give
                                                 it a new expiration time). Defaults to ``False``.
==============================================   =============================================

.. _Totp: https://passlib.readthedocs.io/en/stable/narr/totp-tutorial.html#totp-encryption-setup
.. _set_cookie: https://flask.palletsprojects.com/en/1.1.x/api/?highlight=set_cookie#flask.Response.set_cookie
.. _axios: https://github.com/axios/axios
.. _cachetools: https://pypi.org/project/cachetools/


URLs and Views
--------------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

============================================ ================================================
``SECURITY_LOGIN_URL``                       Specifies the login URL. Defaults to ``/login``.
``SECURITY_LOGOUT_URL``                      Specifies the logout URL. Defaults to
                                             ``/logout``.
``SECURITY_REGISTER_URL``                    Specifies the register URL. Defaults to
                                             ``/register``.
``SECURITY_RESET_URL``                       Specifies the password reset URL. Defaults to
                                             ``/reset``.
``SECURITY_CHANGE_URL``                      Specifies the password change URL. Defaults to
                                             ``/change``.
``SECURITY_CONFIRM_URL``                     Specifies the email confirmation URL. Defaults
                                             to ``/confirm``.
``SECURITY_TWO_FACTOR_SETUP_URL``            Specifies the two factor setup URL. Defaults to ``/tf-setup``.
``SECURITY_TWO_FACTOR_TOKEN_VALIDATION_URL`` Specifies the two factor token validation URL.
                                             Defaults to ``/tf-validate``.
``SECURITY_TWO_FACTOR_QRCODE_URL``           Specifies the two factor request QrCode URL.
                                             Defaults to ``/tf-qrcode``.
``SECURITY_TWO_FACTOR_RESCUE_URL``           Specifies the two factor rescue URL.
                                             Defaults to ``/tf-rescue``.
``SECURITY_TWO_FACTOR_CONFIRM_URL``          Specifies the two factor password confirmation URL.
                                             Defaults to ``/tf-confirm``.
``SECURITY_POST_LOGIN_VIEW``                 Specifies the default view to redirect to after
                                             a user logs in. This value can be set to a URL
                                             or an endpoint name. Defaults to ``/``.
``SECURITY_POST_LOGOUT_VIEW``                Specifies the default view to redirect to after
                                             a user logs out. This value can be set to a URL
                                             or an endpoint name. Defaults to ``/``.
``SECURITY_CONFIRM_ERROR_VIEW``              Specifies the view to redirect to if a
                                             confirmation error occurs. This value can be set
                                             to a URL or an endpoint name. If this value is
                                             ``None``, the user is presented the default view
                                             to resend a confirmation link.
                                             In the case of ``SECURITY_REDIRECT_BEHAVIOR`` == ``spa``
                                             query params in the redirect will contain the error.
                                             Defaults to``None``.
``SECURITY_POST_REGISTER_VIEW``              Specifies the view to redirect to after a user
                                             successfully registers. This value can be set to
                                             a URL or an endpoint name. If this value is
                                             ``None``, the user is redirected to the value of
                                             ``SECURITY_POST_LOGIN_VIEW``. Defaults to
                                             ``None``.
``SECURITY_POST_CONFIRM_VIEW``               Specifies the view to redirect to after a user
                                             successfully confirms their email. This value
                                             can be set to a URL or an endpoint name. If this
                                             value is ``None``, the user is redirected  to the
                                             value of ``SECURITY_POST_LOGIN_VIEW``. Defaults
                                             to ``None``.
``SECURITY_POST_RESET_VIEW``                 Specifies the view to redirect to after a user
                                             successfully resets their password. This value
                                             can be set to a URL or an endpoint name. If this
                                             value is ``None``, the user is redirected  to the
                                             value of ``SECURITY_POST_LOGIN_VIEW``. Defaults
                                             to ``None``.
``SECURITY_POST_CHANGE_VIEW``                Specifies the view to redirect to after a user
                                             successfully changes their password. This value
                                             can be set to a URL or an endpoint name. If this
                                             value is ``None``, the user is redirected  to the
                                             value of ``SECURITY_POST_LOGIN_VIEW``. Defaults
                                             to ``None``.
``SECURITY_UNAUTHORIZED_VIEW``               Specifies the view to redirect to if a user
                                             attempts to access a URL/endpoint that they do
                                             not have permission to access. If this value is
                                             ``None``, the user is presented with a default
                                             HTTP 403 response. Defaults to ``None``.
``SECURITY_RESET_VIEW``                      Specifies the view/URL to redirect to after a GET
                                             reset-password link. This is only valid if
                                             ``SECURITY_REDIRECT_BEHAVIOR`` == ``spa``. Query params
                                             in the redirect will contain the token and email.
                                             Defaults to ``None``
``SECURITY_RESET_ERROR_VIEW``                Specifies the view/URL to redirect to after a GET
                                             reset-password link when there is an error. This is only valid if
                                             ``SECURITY_REDIRECT_BEHAVIOR`` == ``spa``. Query params
                                             in the redirect will contain the error.
                                             Defaults to ``None``
``SECURITY_LOGIN_ERROR_VIEW``                Specifies the view/URL to redirect to after a GET
                                             passwordless link when there is an error. This is only valid if
                                             ``SECURITY_REDIRECT_BEHAVIOR`` == ``spa``. Query params
                                             in the redirect will contain the error.
                                             Defaults to ``None``
============================================ ================================================


Template Paths
--------------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

================================================== =======================================
``SECURITY_FORGOT_PASSWORD_TEMPLATE``              Specifies the path to the template for
                                                   the forgot password page. Defaults to
                                                   ``security/forgot_password.html``.
``SECURITY_LOGIN_USER_TEMPLATE``                   Specifies the path to the template for
                                                   the user login page. Defaults to
                                                   ``security/login_user.html``.
``SECURITY_REGISTER_USER_TEMPLATE``                Specifies the path to the template for
                                                   the user registration page. Defaults to
                                                   ``security/register_user.html``.
``SECURITY_RESET_PASSWORD_TEMPLATE``               Specifies the path to the template for
                                                   the reset password page. Defaults to
                                                   ``security/reset_password.html``.
``SECURITY_CHANGE_PASSWORD_TEMPLATE``              Specifies the path to the template for
                                                   the change password page. Defaults to
                                                   ``security/change_password.html``.
``SECURITY_SEND_CONFIRMATION_TEMPLATE``            Specifies the path to the template for
                                                   the resend confirmation instructions
                                                   page. Defaults to
                                                   ``security/send_confirmation.html``.
``SECURITY_SEND_LOGIN_TEMPLATE``                   Specifies the path to the template for
                                                   the send login instructions page for
                                                   passwordless logins. Defaults to
                                                   ``security/send_login.html``.
``SECURITY_TWO_FACTOR_VERIFY_CODE_TEMPLATE``       Specifies the path to the template for
                                                   the verify code page for the two-factor
                                                   authentication process. Defaults to
                                                   ``security/two_factor_verify_code.html``.
``SECURITY_TWO_FACTOR_SETUP_TEMPLATE``             Specifies the path to the template for
                                                   the setup page for the two
                                                   factor authentication process. Defaults
                                                   to ``security/two_factor_setup.html``
``SECURITY_TWO_FACTOR_VERIFY_PASSWORD_TEMPLATE``   Specifies the path to the template for
                                                   the change method page for the two
                                                   factor authentication process. Defaults
                                                   to ``security/two_factor_verify_password.html``.

================================================== =======================================


Feature Flags
-------------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

========================= ======================================================
``SECURITY_CONFIRMABLE``  Specifies if users are required to confirm their email
                          address when registering a new account. If this value
                          is `True`, Flask-Security creates an endpoint to handle
                          confirmations and requests to resend confirmation
                          instructions. The URL for this endpoint is specified
                          by the ``SECURITY_CONFIRM_URL`` configuration option.
                          Defaults to ``False``.
``SECURITY_REGISTERABLE`` Specifies if Flask-Security should create a user
                          registration endpoint. The URL for this endpoint is
                          specified by the ``SECURITY_REGISTER_URL``
                          configuration option. Defaults to ``False``.
``SECURITY_RECOVERABLE``  Specifies if Flask-Security should create a password
                          reset/recover endpoint. The URL for this endpoint is
                          specified by the ``SECURITY_RESET_URL`` configuration
                          option. Defaults to ``False``.
``SECURITY_TRACKABLE``    Specifies if Flask-Security should track basic user
                          login statistics. If set to ``True``, ensure your
                          models have the required fields/attributes
                          and make sure to commit changes after calling
                          ``login_user``. Be sure to use `ProxyFix <http://flask.pocoo.org/docs/0.10/deploying/wsgi-standalone/#proxy-setups>`_ if you are using a proxy.
                          Defaults to ``False``
``SECURITY_PASSWORDLESS`` Specifies if Flask-Security should enable the
                          passwordless login feature. If set to ``True``, users
                          are not required to enter a password to login but are
                          sent an email with a login link. This feature is
                          experimental and should be used with caution. Defaults
                          to ``False``.
``SECURITY_CHANGEABLE``   Specifies if Flask-Security should enable the
                          change password endpoint. The URL for this endpoint is
                          specified by the ``SECURITY_CHANGE_URL`` configuration
                          option. Defaults to ``False``.
``SECURITY_TWO_FACTOR``   Specifies if Flask-Security should enable the
                          two-factor login feature. If set to ``True``, in
                          addition to their passwords, users will be required to
                          enter a code that is sent to them. Note that unless
                          ``SECURITY_TWO_FACTOR_REQUIRED`` is set - this is
                          opt-in.
                          Defaults to ``False``.
========================= ======================================================

Email
----------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

================================================= ==============================
``SECURITY_EMAIL_SUBJECT_REGISTER``               Sets the subject for the
                                                  confirmation email. Defaults
                                                  to ``Welcome``
``SECURITY_EMAIL_SUBJECT_PASSWORDLESS``           Sets the subject for the
                                                  passwordless feature. Defaults
                                                  to ``Login instructions``
``SECURITY_EMAIL_SUBJECT_PASSWORD_NOTICE``        Sets subject for the password
                                                  notice. Defaults to ``Your
                                                  password has been reset``
``SECURITY_EMAIL_SUBJECT_PASSWORD_RESET``         Sets the subject for the
                                                  password reset email. Defaults
                                                  to ``Password reset
                                                  instructions``
``SECURITY_EMAIL_SUBJECT_PASSWORD_CHANGE_NOTICE`` Sets the subject for the
                                                  password change notice.
                                                  Defaults to ``Your password
                                                  has been changed``
``SECURITY_EMAIL_SUBJECT_CONFIRM``                Sets the subject for the email
                                                  confirmation message. Defaults
                                                  to ``Please confirm your
                                                  email``
``SECURITY_EMAIL_PLAINTEXT``                      Sends email as plaintext using
                                                  ``*.txt`` template. Defaults
                                                  to ``True``.
``SECURITY_EMAIL_HTML``                           Sends email as HTML using
                                                  ``*.html`` template. Defaults
                                                  to ``True``.
``SECURITY_EMAIL_SUBJECT_TWO_FACTOR``             Sets the subject for the two
                                                  factor feature. Defaults to
                                                  ``Two-factor Login``
``SECURITY_EMAIL_SUBJECT_TWO_FACTOR_RESCUE``      Sets the subject for the two
                                                  factor help function. Defaults
                                                  to ``Two-factor Rescue``
================================================= ==============================

Miscellaneous
-------------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

===================================================== ==================================
``SECURITY_USER_IDENTITY_ATTRIBUTES``                 Specifies which attributes of the
                                                      user object can be used for login.
                                                      Defaults to ``['email']``.
``SECURITY_SEND_REGISTER_EMAIL``                      Specifies whether registration
                                                      email is sent. Defaults to
                                                      ``True``.
``SECURITY_SEND_PASSWORD_CHANGE_EMAIL``               Specifies whether password change
                                                      email is sent. Defaults to
                                                      ``True``.
``SECURITY_SEND_PASSWORD_RESET_EMAIL``                Specifies whether password reset
                                                      email is sent. Defaults to
                                                      ``True``.
``SECURITY_SEND_PASSWORD_RESET_NOTICE_EMAIL``         Specifies whether password reset
                                                      notice email is sent. Defaults to
                                                      ``True``.

``SECURITY_CONFIRM_EMAIL_WITHIN``                     Specifies the amount of time a
                                                      user has before their confirmation
                                                      link expires. Always pluralized
                                                      the time unit for this value.
                                                      Defaults to ``5 days``.
``SECURITY_RESET_PASSWORD_WITHIN``                    Specifies the amount of time a
                                                      user has before their password
                                                      reset link expires. Always
                                                      pluralized the time unit for this
                                                      value. Defaults to ``5 days``.
``SECURITY_LOGIN_WITHIN``                             Specifies the amount of time a
                                                      user has before a login link
                                                      expires. This is only used when
                                                      the passwordless login feature is
                                                      enabled. Always pluralize the
                                                      time unit for this value.
                                                      Defaults to ``1 days``.
``SECURITY_AUTO_LOGIN_AFTER_CONFIRM``                 If ``False`` then on confirmation
                                                      the user will be required to login again. Note that the
                                                      confirmation token is not valid after being used once.
                                                      If ``True``, then the user corresponding to the
                                                      confirmation token will be automatically logged
                                                      in.
                                                      Defaults to ``True``.
``SECURITY_TWO_FACTOR_GOOGLE_AUTH_VALIDITY``          Specifies the number of seconds access token is
                                                      valid. Defaults to 2 minutes.
``SECURITY_TWO_FACTOR_MAIL_VALIDITY``                 Specifies the number of seconds
                                                      access token is valid. Defaults to 5 minutes.
``SECURITY_TWO_FACTOR_SMS_VALIDITY``                  Specifies the number of seconds access token is
                                                      valid. Defaults to 2 minutes.
``SECURITY_LOGIN_WITHOUT_CONFIRMATION``               Specifies if a user may login
                                                      before confirming their email when
                                                      the value of
                                                      ``SECURITY_CONFIRMABLE`` is set to
                                                      ``True``. Defaults to ``False``.
``SECURITY_CONFIRM_SALT``                             Specifies the salt value when
                                                      generating confirmation
                                                      links/tokens. Defaults to
                                                      ``confirm-salt``.
``SECURITY_RESET_SALT``                               Specifies the salt value when
                                                      generating password reset
                                                      links/tokens. Defaults to
                                                      ``reset-salt``.
``SECURITY_LOGIN_SALT``                               Specifies the salt value when
                                                      generating login links/tokens.
                                                      Defaults to ``login-salt``.
``SECURITY_REMEMBER_SALT``                            Specifies the salt value when
                                                      generating remember tokens.
                                                      Remember tokens are used instead
                                                      of user ID's as it is more
                                                      secure. Defaults to
                                                      ``remember-salt``.
``SECURITY_DEFAULT_REMEMBER_ME``                      Specifies the default "remember
                                                      me" value used when logging in
                                                      a user. Defaults to ``False``.
``SECURITY_TWO_FACTOR_REQUIRED``                      If set to ``True`` then all users will be
                                                      required to setup and use two factor authorization.
                                                      Defaults to ``False``.
``SECURITY_TWO_FACTOR_ENABLED_METHODS``               Specifies the default enabled
                                                      methods for two-factor
                                                      authentication. Defaults to
                                                      ``['mail', 'google_authenticator',
                                                      'sms']`` which are the only
                                                      supported method at the moment.
``SECURITY_TWO_FACTOR_URI_SERVICE_NAME``              Specifies the name of the service
                                                      or application that the user is
                                                      authenticating to. Defaults to
                                                      ``service_name``
``SECURITY_TWO_FACTOR_SMS_SERVICE``                   Specifies the name of the sms
                                                      service provider. Defaults to
                                                      ``Dummy`` which does nothing.
``SECURITY_TWO_FACTOR_SMS_SERVICE_CONFIG``            Specifies a dictionary of basic
                                                      configurations needed for use of a
                                                      sms service. Defaults to
                                                      ``{'ACCOUNT_ID': NONE, 'AUTH_TOKEN
                                                      ':NONE, 'PHONE_NUMBER': NONE}``
``SECURITY_DATETIME_FACTORY``                         Specifies the default datetime
                                                      factory. Defaults to
                                                      ``datetime.datetime.utcnow``.
``SECURITY_BACKWARDS_COMPAT_UNAUTHN``                 If set to ``True`` then the default behavior for authentication
                                                      failures from one of Flask-Security's decorators will be restored to
                                                      be compatible with releases prior to 3.3.0 (return 401 and some static html).
                                                      Defaults to ``False``.
``SECURITY_BACKWARDS_COMPAT_AUTH_TOKEN``              If set to ``True`` then an Authentication-Token will be returned
                                                      on every successful call to login, reset-password, change-password
                                                      as part of the JSON response. This was the default prior to release 3.3.0
                                                      - however sending Authentication-Tokens (which by default don't expire)
                                                      to session based UIs is a bad security practice.
                                                      Defaults to ``False``.
``SECURITY_BACKWARDS_COMPAT_AUTH_TOKEN_INVALIDATE``   When ``True`` changing the user's password will also change the user's
                                                      ``fs_uniquifier`` (if it exists) such that existing authentication tokens
                                                      will be rendered invalid.  This restores pre 3.3.0 behavior.
===================================================== ==================================

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
