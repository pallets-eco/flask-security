API
===

The external (json/form) API is described `here`_

.. _here: _static/openapi_view.html


Core
----
.. autoclass:: flask_security.Security
    :members:

.. data:: flask_security.current_user

   A proxy for the current user.

.. function:: flask_security.Security.unauthorized_handler

    If an endpoint fails authentication or authorization from one of the decorators
    described below
    (except ``login_required``), a method annotated with this decorator will be called.
    For ``login_required`` (which is implemented in Flask-Login) use
    **flask_security.login_manager.unauthorized_handler**

    .. deprecated:: 3.3.0

Protecting Views
----------------
.. autofunction:: flask_security.anonymous_user_required

.. autofunction:: flask_security.http_auth_required

.. autofunction:: flask_security.auth_token_required

.. autofunction:: flask_security.auth_required

.. autofunction:: flask_security.login_required

.. autofunction:: flask_security.roles_required

.. autofunction:: flask_security.roles_accepted

.. autofunction:: flask_security.permissions_required

.. autofunction:: flask_security.permissions_accepted

.. autofunction:: flask_security.unauth_csrf

.. autofunction:: flask_security.handle_csrf

User Object Helpers
-------------------
.. autoclass:: flask_security.UserMixin
   :members:

.. autoclass:: flask_security.RoleMixin
   :members:

.. autoclass:: flask_security.WebAuthnMixin
   :members:

.. autoclass:: flask_security.AnonymousUser
   :members:


Datastores
----------
.. autoclass:: flask_security.UserDatastore
    :members:

.. autoclass:: flask_security.SQLAlchemyUserDatastore
    :show-inheritance:

.. autoclass:: flask_security.SQLAlchemySessionUserDatastore
    :show-inheritance:

.. autoclass:: flask_security.MongoEngineUserDatastore
    :show-inheritance:

.. autoclass:: flask_security.PeeweeUserDatastore
    :show-inheritance:

.. autoclass:: flask_security.PonyUserDatastore
    :show-inheritance:

.. autoclass:: flask_security.datastore.SQLAlchemyDatastore

    Internal class implementing DataStore interface.

.. autoclass:: flask_security.datastore.MongoEngineDatastore

    Internal class implementing DataStore interface.

.. autoclass:: flask_security.datastore.PeeweeDatastore

    Internal class implementing DataStore interface.

.. autoclass:: flask_security.datastore.PonyDatastore

    Internal class implementing DataStore interface.

.. class:: User

    The User model. This must be provided by the application.
    See :ref:`Models <models_topic>`.

.. class:: Role

    The Role model. This must be provided by the application.
    See :ref:`Models <models_topic>`.

.. class:: WebAuthn

    The WebAuthn model. This must be provided by the application.
    See :ref:`Models <models_topic>`.

Utils
-----
.. autofunction:: flask_security.lookup_identity

.. autofunction:: flask_security.login_user

.. autofunction:: flask_security.logout_user

.. autofunction:: flask_security.check_and_update_authn_fresh

.. autofunction:: flask_security.get_hmac

.. autofunction:: flask_security.get_request_attr

.. autofunction:: flask_security.verify_password

.. autofunction:: flask_security.verify_and_update_password

.. autofunction:: flask_security.hash_password

.. autofunction:: flask_security.admin_change_password

.. autofunction:: flask_security.uia_phone_mapper

.. autofunction:: flask_security.uia_email_mapper

.. autofunction:: flask_security.uia_username_mapper

.. autofunction:: flask_security.url_for_security

.. autofunction:: flask_security.send_mail

.. autofunction:: flask_security.get_token_status

.. autofunction:: flask_security.check_and_get_token_status

.. autofunction:: flask_security.get_url

.. autofunction:: flask_security.password_length_validator

.. autofunction:: flask_security.password_complexity_validator

.. autofunction:: flask_security.password_breached_validator

.. autofunction:: flask_security.pwned

.. autofunction:: flask_security.transform_url

.. autofunction:: flask_security.unique_identity_attribute

.. autofunction:: flask_security.us_send_security_token

.. autofunction:: flask_security.tf_send_security_token

.. autoclass:: flask_security.AsaList

.. autoclass:: flask_security.SmsSenderBaseClass
  :members: send_sms

.. autoclass:: flask_security.SmsSenderFactory
  :members: createSender

.. autoclass:: flask_security.OAuthGlue
  :members:


Extendable Classes
------------------
Each of the following classes can be extended and passed in as part of
Security() instantiation.

.. autoclass:: flask_security.PhoneUtil
  :members:
  :special-members: __init__

.. autoclass:: flask_security.MailUtil
  :members:
  :special-members: __init__

.. autoclass:: flask_security.PasswordUtil
  :members:
  :special-members: __init__

.. autoclass:: flask_security.MfRecoveryCodesUtil
  :members:
  :special-members: __init__

.. autoclass:: flask_security.UsernameUtil
  :members:
  :special-members: __init__

.. autoclass:: flask_security.WebauthnUtil
  :members:
  :special-members: __init__

.. autoclass:: flask_security.Totp
  :members: get_last_counter, set_last_counter, generate_qrcode


Forms
-----

.. autoclass:: flask_security.ChangePasswordForm
.. autoclass:: flask_security.ConfirmRegisterForm
.. autoclass:: flask_security.ForgotPasswordForm
.. autoclass:: flask_security.LoginForm
.. autoclass:: flask_security.MfRecoveryCodesForm
.. autoclass:: flask_security.MfRecoveryForm
.. autoclass:: flask_security.PasswordlessLoginForm
.. autoclass:: flask_security.RegisterForm
.. autoclass:: flask_security.ResetPasswordForm
.. autoclass:: flask_security.SendConfirmationForm
.. autoclass:: flask_security.TwoFactorVerifyCodeForm
.. autoclass:: flask_security.TwoFactorSetupForm
.. autoclass:: flask_security.TwoFactorSelectForm
.. autoclass:: flask_security.TwoFactorRescueForm
.. autoclass:: flask_security.UnifiedSigninForm
.. autoclass:: flask_security.UnifiedSigninSetupForm
.. autoclass:: flask_security.UnifiedSigninSetupValidateForm
.. autoclass:: flask_security.UnifiedVerifyForm
.. autoclass:: flask_security.VerifyForm
.. autoclass:: flask_security.WebAuthnRegisterForm
.. autoclass:: flask_security.WebAuthnRegisterResponseForm
.. autoclass:: flask_security.WebAuthnSigninForm
.. autoclass:: flask_security.WebAuthnSigninResponseForm
.. autoclass:: flask_security.WebAuthnDeleteForm
.. autoclass:: flask_security.WebAuthnVerifyForm
.. autoclass:: flask_security.Form
.. autoclass:: flask_security.FormInfo

.. _signals_topic:

Signals
-------
See the `Flask documentation on signals`_ for information on how to use these
signals in your code.

.. tip::

    Remember to add ``**extra_args`` to your signature so that if we add
    additional parameters in the future your code doesn't break.

See the documentation for the signals provided by the Flask-Login and
Flask-Principal extensions. In addition to those signals, Flask-Security
sends the following signals.

.. data:: user_authenticated

    Sent when a user successfully authenticates. In addition to the app (which is the
    sender), it is passed `user`, and `authn_via` arguments. The `authn_via` argument
    specifies how the user authenticated - it will be a list with possible values
    of ``password``, ``sms``, ``authenticator``, ``email``, ``confirm``, ``reset``,
    ``register``.

    .. versionadded:: 3.4.0

.. data:: user_registered

   Sent when a user registers on the site. In addition to the app (which is the
   sender), it is passed `user`, `confirm_token` (deprecated), `confirmation_token` and `form_data` arguments.
   `form_data` is a dictionary representation of registration form's content
   received with the registration request.

.. data:: user_not_registered

    Sent when a user attempts to register, but is already registered. This is ONLY sent
    when :py:data:`SECURITY_RETURN_GENERIC_RESPONSES` is enabled. It is passed the
    following arguments:

        * `user` - The existing user model
        * `existing_email` - True if attempting to register an existing email
        * `existing_username`- True if attempting to register an existing username
        * `form_data` - the entire contents of the posted request form

    .. versionadded:: 5.0.0

.. data:: user_confirmed

   Sent when a user is confirmed. In addition to the app (which is the
   sender), it is passed a `user` argument.

.. data:: confirm_instructions_sent

   Sent when a user requests confirmation instructions. In addition to the app
   (which is the sender), it is passed a `user` and `confirmation_token` arguments.

.. data:: login_instructions_sent

   Sent when passwordless login is used and user logs in. In addition to the app
   (which is the sender), it is passed `user` and `login_token` arguments.

.. data:: password_reset

   Sent when a user completes a password reset. In addition to the app (which is
   the sender), it is passed a `user` argument.

.. data:: password_changed

   Sent when a user completes a password change. In addition to the app (which is
   the sender), it is passed a `user` argument.

.. data:: reset_password_instructions_sent

   Sent when a user requests a password reset. In addition to the app (which is
   the sender), it is passed `user`, `token` (deprecated), and `reset_token` arguments.

.. data:: tf_code_confirmed

    Sent when a user performs two-factor authentication login on the site. In
    addition to the app (which is the sender), it is passed `user`
    and `method` arguments.

    .. versionadded:: 3.3.0

.. data:: tf_profile_changed

    Sent when two-factor is used and user logs in. In addition to the app
    (which is the sender), it is passed `user` and `method` arguments.

    .. versionadded:: 3.3.0

.. data:: tf_disabled

    Sent when two-factor is disabled. In addition to the app
    (which is the sender), it is passed `user` argument.

    .. versionadded:: 3.3.0

.. data:: tf_security_token_sent

    Sent when a two factor security/access code is sent. In addition to the app
    (which is the sender), it is passed `user`, `method`, `login_token` and `token` (deprecated) arguments.

    .. versionadded:: 3.3.0

.. data:: us_security_token_sent

    Sent when a unified sign in access code is sent. In addition to the app
    (which is the sender), it is passed `user`, `method`, `token` (deprecated),
    `login_token`,
    `phone_number`, and `send_magic_link` arguments.

    .. versionadded:: 3.4.0

.. data:: us_profile_changed

    Sent when user completes changing their unified sign in profile. In addition to the app
    (which is the sender), it is passed `user`, `methods`, and `delete` arguments.
    `delete` will be set to ``True`` if the user removed a sign in option.

    .. versionadded:: 3.4.0

    .. versionchanged:: 5.0.0
        Added delete argument and changed `method` to `methods` which is now a list.

.. data:: wan_registered

    Sent when a WebAuthn credential was successfully created. In addition to the app
    (which is the sender), it is passed `user` and `name` arguments.

    .. versionadded:: 5.0.0

.. data:: wan_deleted

    Sent when a WebAuthn credential was deleted. In addition to the app
    (which is the sender), it is passed `user` and `name` arguments.

    .. versionadded:: 5.0.0

.. _Flask documentation on signals: https://flask.palletsprojects.com/en/2.0.x/signals/
