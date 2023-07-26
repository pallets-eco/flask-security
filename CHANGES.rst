Flask-Security Changelog
========================

Here you can see the full list of changes between each Flask-Security release.

Version 5.3.0
-------------

Released July 27, 2023

This is a minor version bump due to some small backwards incompatible changes to
WebAuthn, recoverability (/reset), confirmation (/confirm) and the two factor validity feature.

Fixes
++++++

- (:pr:`807`) Webauthn Updates to handling of transport.
- (:pr:`809`) Fix MongoDB support by eliminating dependency on flask-mongoengine.
  Improve MongoDB quickstart.
- (:issue:`801`) Fix Quickstart for SQLAlchemy with scoped session.
- (:issue:`806`) Login no longer, by default, checks for email deliverability.
- (:issue:`791`) Token authentication is no longer accepted on endpoints which only allow
  'session' as authentication-method. (N247S)
- (:issue:`814`) /reset and /confirm and GENERIC_RESPONSES and additional form args don't mix.
- (:issue:`281`) Reset password can be exploited and other OWASP improvements.
- (:pr:`817`) Confirmation can be exploited and other OWASP improvements.
- (:pr:`819`) Convert to pyproject.toml, build, remove setup.py/.cfg.
- (:pr:`823`) the tf_validity feature now ONLY sets a cookie - and the token is no longer
  returned as part of a JSON response.
- (:pr:`825`) Fix login/unified signin templates to properly send CSRF token. Add more tests.
- (:pr:`826`) Improve Social Oauth example code.

Backwards Compatibility Concerns
+++++++++++++++++++++++++++++++++

- To align with the W3C WebAuthn Level2 and 3 spec - transports are now part of the registration response.
  This has been changed BOTH in the server code (using webauthn data structures) as well as the sample
  javascript code. If an application has their own javascript front end code - it might need to be changed.
- The tf_validity feature :py:data`SECURITY_TWO_FACTOR_ALWAYS_VALIDATE` used to set a cookie if the request was
  form based, and return the token as part of a JSON response. Now, this feature is ONLY cookie based and the token
  is no longer returned as part of any response.
- Reset password was changed to adhere to OWASP recommendations and reduce possible exploitation:

    - A new email (with new token) is no longer sent upon expired token. Users must restart
      the reset password process.
    - The user is no longer automatically logged in upon successful password reset. For
      backwards compatibility :py:data:`SECURITY_AUTO_LOGIN_AFTER_RESET` can be set to ``True``.
      Note that this compatibility feature is deprecated and will be removed in a future release.
    - Identity information (identity, email) is no longer sent as part of the URL redirect
      query params.
    - The SECURITY_MSG_PASSWORD_RESET_EXPIRED message no longer contains the user's identity/email.
    - The default for :py:data:`SECURITY_RESET_PASSWORD_WITHIN` has been changed from `5 days` to `1 days`.
    - The response to GET /reset/<token> sets the HTTP header `Referrer-Policy` to `no-referrer` as suggested
      by OWASP.
- Confirm email was changed to adhere to OWASP recommendations and reduce possible exploitation:

    - A new email (with new token) is no longer sent upon expired token. Users must restart
      the confirmation process.
    - Identity information (identity, email) is no longer sent as part of the URL redirect
      query params.
    - The :py:data:`SECURITY_AUTO_LOGIN_AFTER_CONFIRM` configuration variable now defaults to ``False`` - meaning
      after a successful email confirmation, the user must still sign in using the usual mechanisms. This is to
      align better with OWASP best practices. Setting it to ``True`` will restore prior behavior.
    - The SECURITY_MSG_CONFIRMATION_EXPIRED message no longer contains the user's identity/email.
    - The response to GET /reset/<token> sets the HTTP header `Referrer-Policy` to `no-referrer` as suggested
      by OWASP.

Version 5.2.0
-------------

Released May 6, 2023

Note: Due to rapid deprecation and removal of APIs from the Pallets team,
maintaining the testing of back versions of various packages is taking too
much time and effort. In this release only current versions of the various
dependent packages are being tested.

Fixes
+++++

- (:issue:`764`) Remove old Werkzeug compatibility check.
- (:issue:`777`) Compatibility with Quart.
- (:pr:`780`) Remove dependence on pkg_resources / setuptools (use importlib_resources package)
- (:pr:`792`) Fix tests to work with latest Werkzeug/Flask. Update requirements_low to match current releases.
- (:pr:`792`) Drop support for Python 3.7

Known Issues
++++++++++++

- Flask-mongoengine hasn't released in a while and currently will not work with latest Flask and Flask-Security-Too
  (this is due to the JSONEncoder being deprecated and removed).

Backwards Compatibility Concerns
+++++++++++++++++++++++++++++++++
- The removal of pkg_resources required changing the config variable :py:data:`SECURITY_I18N_DIRNAME`.
  If your application modified or extended this configuration variable, a small change will be required.

Version 5.1.2
-------------

Released March 12, 2023

Fixes
+++++

- (:issue:`771`) Hungarian translations not working.
- (:pr:`769`) Fix documentation for send_mail. (gg)
- (:pr:`768`) Fix for latest mongoengine and mongomock.
- (:pr:`766`) Fix inappropriate use of &thinsp& in French translations. (maxdup)
- (:pr:`773`) Improve documentation around subclassing forms.

Version 5.1.1
-------------

Released March 1, 2023

Fixes
+++++

- (:issue:`740`) Fix 2 Flask apps in same thread with USERNAME_ENABLE set.
  There was a too aggressive config check.
- (:pr:`739`) Update Russian translations. (ademaro)
- (:pr:`743`) Run all templates through a linter. (ademaro)
- (:pr:`757`) Fix json/flask backwards compatibility hack.
- (:issue:`759`) Fix quickstarts - make sure they run using `flask run`
- (:pr:`755`) Fix unified signup when two-factor not enabled. (sebdroid)
- (:pr:`763`) Add dependency on setuptools (pkg_resources). (hroncok)

Version 5.1.0
-------------

Released January 23, 2023

Features
++++++++

- (:issue:`667`) Expose form instantiation. See :ref:`form_instantiation`.
- (:issue:`693`) Option to encrypt recovery codes.
- (:pr:`716`) Support for authentication via 'social' oauth.
- (:pr:`721`) Support for Python 3.11

Fixes
+++++

- (:pr:`678`) Fixes for Flask-SQLAlchemy 3.0.0. (jrast)
- (:pr:`680`) Fixes for sqlalchemy 2.0.0 (jrast)
- (:issue:`697`) Webauthn and Unified signin features now properly take into
  account blueprint prefixes.
- (:issue:`699`) Properly propagate `?next=/xx` - the verify, webauthn, and unified
  signin endpoints, that had multiple redirects, needed fixes.
- (:pr:`696`) Add Hungarian translations. (xQwexx)
- (:issue:`701`) Two factor redirects ignored url_prefix. Added a :py:data:`SECURITY_TWO_FACTOR_ERROR_VIEW`
  configuration option.
- (:issue:`704`) Add configurations for static folder/URL and make sure templates reference
  blueprint relative static folder.
- (:issue:`709`) Make (some) templates look better by using single quotes instead of
  double quotes.
- (:issue:`690`) Send entire context to MailUtil::send_mail (patrickyan)
- (:pr:`728`) Support for Flask-Babel 3.0.0
- (:issue:`692`) Add configuration option :py:data:`SECURITY_TWO_FACTOR_POST_SETUP_VIEW` which
  is redirected to upon successful change of a two factor method.
- (:pr:`733`) The ability to pass in a LoginManager instance which was deprecated in
  5.0 has been removed.
- (:issue:`732`) If :py:data:`SECURITY_USERNAME_REQUIRED` was ``True`` then users couldn't login
  with just an email.
- (:issue:`734`) If :py:data:`SECURITY_USERNAME_ENABLE` is set, bleach is a requirement.
- (:pr:`736`) The unauthz_handler now takes a function name, not the function!

Backwards Compatibility Concerns
+++++++++++++++++++++++++++++++++

- Each form class used to be set as an attribute on the Security object. With
  the new form instantiation model, they no longer are.
- After a successful update/change of a two-factor method, the user was redirected to
  :py:data:`SECURITY_POST_LOGIN_VIEW`. Now it redirects to :py:data:`SECURITY_TWO_FACTOR_POST_SETUP_VIEW`
  which defaults to `".two_factor_setup"`.
- The :meth:`.Security.unauthz_handler` now takes a function name - not the function -
  which never made sense.

Version 5.0.2
-------------

Released September 23, 2022

Fixes
+++++
- (:issue:`673`) Role permissions backwards compatibility bug. For SQL based datastores
  that use Flask-Security's models.fsqla_vx - there should be NO issues. If you declare
  your own models - please see the 5.0.0 releases notes for required change.

Version 5.0.1
-------------

Released September 6, 2022

Fixes
+++++
- (:pr:`662`) Fix Change Password regression. (tysonholub)

Version 5.0.0
-------------

Released August 27. 2022

**PLEASE READ CHANGE NOTES CAREFULLY - THERE ARE LIKELY REQUIRED CHANGES YOU WILL HAVE TO MAKE.**

Features
++++++++
- (:issue:`475`) Support for WebAuthn.
- (:issue:`479`) Support Two-factor recovery codes.
- (:issue:`585`) Provide option to prevent user enumeration (i.e. Generic Responses).
- (:pr:`532`) Support for Python 3.10.
- (:pr:`657`, :pr:`655`) Support for Flask >= 2.2.
- (:pr:`540`) Improve Templates in support of JS required by WebAuthn.
- (:pr:`608`) Add Icelandic translations. (ofurkusi)
- (:pr:`650`) Update German translations. (sr-verde)
- (:issue:`256`) Add custom HTML attributes to improve user experience.
  This changed LoginForm quite a bit - please see backwards compatability concerns
  below. The default LoginForm and template should be the same as before.
- (:pr:`638`) The JSON errors response has been unified. Please see backwards
  compatibility concerns below.
- Updated all-inclusive data models (fsqla_v3). Add fields necessary for the new WebAuthn and
  Two-Factor recovery codes features.
  Changed `us_phone_number` to be unique (but not required). Changed `password` to be nullable.

Deprecations
++++++++++++
- (:pr:`568`) Deprecate the old passwordless feature in favor of Unified Signin.
- (:pr:`568`) Deprecate replacing login_manager so we can possibly vendor that in in the future.
- (:pr:`654`) The previously deprecated methods RoleMixin.add_permissions and
  RoleMixin.remove_permissions have been removed.
- (:pr:`657`) The ability to pass in a json_encoder_cls as part of initialization has been removed
  since Flask 2.2 has deprecated and replaced that functionality.
- (:pr:`655`) Flask has deprecated @before_first_request. This was used mostly in examples/quickstart.
  These have been changed to use app.app_context() prior to running the app. Flask-Security itself used it in
  2 places - to populate `_` in jinja globals if Babel wasn't initialized and to perform
  various configuration sanity checks w.r.t. WTF CSRF. All Flask-Security templates have been converted
  to use `_fsdomain` rather than ``_`` so Flask-Security no longer sets ``_`` into jinja2 globals.
  The configuration checks
  have been moved to the end of Security::init_app() - so it is now imperative that `FlaskWTF::CSRFProtect()`
  be called PRIOR to initializing Flask-Security.
- encrypt_password method has been removed. It has been deprecated since 2.0.2
- get_token_status has been deprecated.

Fixes
+++++
- (:pr:`591`) Make the required zxcvbn complexity score configurable. (mephi42)
- (:issue:`531`) Get rid of Flask-Mail. Flask-Mailman is now the default preferred email package.
  Flask-Mail is still supported so there should be no backwards compatability issues.
- (:issue:`597`) A delete option has been added to us-setup (form and view).
- (:pr:`625`) Improve username support - the LoginForm now has a separate field for username if
  ``SECURITY_USERNAME_ENABLE`` is True, and properly displays input fields only if the associated
  field is an identity attribute (as specified by :py:data:`SECURITY_USER_IDENTITY_ATTRIBUTES`).
- (:pr:`627`) Improve empty password handling. Prior, an unguessable password was set into the user
  record when a user registered without a password - now, the DB user model has been changed to
  allow nullable passwords. This provides a better user experience since Flask-Security now
  knows if a user has an empty password or not. Since registering without a password is not
  a mainstream feature, a new configuration variable :py:data:`SECURITY_PASSWORD_REQUIRED`
  has been added (defaults to ``True``).
- (:issue:`479`) A new configuration option :py:data:`SECURITY_TWO_FACTOR_RESCUE_EMAIL` has been added
  that allows disabling that feature - defaults to backwards compatible ``True``
- (:issue:`658`) us_phone_number needs to be validated to be unique.


Backward Compatibility Concerns
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For unified signin:

- The redirect after a successful us-setup used to redirect to ``SECURITY_US_POST_SETUP_VIEW`` or
  ``SECURITY_POST_LOGIN_VIEW`` (which would default to '/'). Now it just redirects to
  ``SECURITY_US_POST_SETUP_VIEW`` which defaults back to the ``/us-setup`` view.
- The ability to authenticate using a one-time email link was automatically setup by the system
  for all users.
  "email" now behaves like the other unified sign in methods and must be explicitly set up - with the
  exception that if a user registers WITHOUT a password, the system will setup the one-time email link
  option - since otherwise the user would never be able to authenticate.
- ``/us-signin/send-code`` didn't used to check if the user account required confirmation it just sent a code
  and the ``/us-signin`` endpoint did the confirmation check. Now ``send-code`` does the confirmation check and
  won't send a code unless the user is confirmed.
- In ``us-verify`` the 'code_methods' item now lists just active/setup methods that generate a code
  not ALL possible methods that generate a code.
- ``SECURITY_US_VERIFY_SEND_CODE_URL`` and ``SECURITY_US_SIGNIN_SEND_CODE_URL`` endpoints are now POST only.
- Empty passwords were always permitted when ``SECURITY_UNIFIED_SIGNIN`` was enabled - now an additional configuration
  variable ``SECURITY_PASSWORD_REQUIRED`` must be set to False.
- ``SECURITY_US_VERIFY_SEND_CODE_URL`` and ``SECURITY_US_SIGNIN_SEND_CODE_URL`` used to send ``code_sent`` to the template.
  Now they flash the ``SECURITY_MSG_CODE_HAS_BEEN_SENT`` message.
- With the addition of being able to delete a previously setup up sign in method, the signal `us_profile_changed` arguments
  have changed. `method` is now `methods` and is a list, and a new argument `delete` is True if a sign in option was deleted.

Login:

- Since the beginning of time, the flask-security login form has accepted any input in the
  'email' field, and used that to check if it corresponds to any field in ``SECURITY_USER_IDENTITY_ATTRIBUTES``.
  This has always been problematic and confusing - and with the addition of HTML attributes for various
  form fields - having a field with multiple possible inputs is no longer a viable user experience.
  This is no longer supported, and the LoginForm now declares the ``email`` field to be of type ``EmailField``
  which requires a valid (after normalization) email address. The most common usage of this legacy feature was to allow
  an email or username - Flask-Security now has core support for a ``username`` option - see :py:data:`SECURITY_USERNAME_ENABLE`.
  Please see :ref:`custom_login_form` for an example of how to replicate the legacy behavior.
- Some error messages have changed - ``USER_DOES_NOT_EXIST`` is now returned for any identity error including an empty value.

Other:

- A very old piece of code in registrable, would immediately commit to the DB when a new user was created.
  It is now consistent with all other views, and has the caller responsible for committing the transaction - usually by
  setting up a flask ``after_this_request`` action. This could affect an application that captured the registration signal
  and stored the ``user`` object for later use - this user object would likely be invalid after the request is finished.
- Some fields have custom HTML attributes attached to them (e.g. autocomplete, type, etc). These are stored as part of the
  form in the ``render_kw`` attribute. This could cause some confusion if an app had its own templates and set different
  attributes.
- The keys for "/tf-rescue" select options have changed to be more 'action' oriented:

    - `lost_device` -> `email`
    - `no_mail_access` -> `help`
- JSON error responses. **THIS IS A BREAKING CHANGE**.
  In earlier releases, the JSON error response could have either a `error` key which was for rare cases
  where there was a single non-form related error, or an `errors` key which was a a dict as defined by WTForms.
  Now, the `errors` key will contain a list of (localized) messages - both non-form related as well as any form related.
  The key `field_errors` will contain the dict as specified by WTForms. Please note that starting with WTForms 3.0
  form-level errors are supported and show up in the dict with the field name/key of "none". There are no changes to non-error
  related JSON responses.
- Permissions **THIS IS A BREAKING CHANGE**. The Role Model now stores permissions as a list, and requires that the underlying DB ORM map that to a supported
  DB type. For SQLAlchemy, this is mapped to a comma separated string (as before). For
  SQLAlchemy DBs the underlying Column type (UnicodeText) didn't change so no data migration should be required.
  However, the ORM Column type did change and requires the following change to your model::

    from flask_security import AsaList
    from sqlalchemy.ext.mutable import MutableList
    class Role(Base, RoleMixin):
        ...
        permissions = Column(MutableList.as_mutable(AsaList()), nullable=True)
        ...

  If your application makes use of Flask-Security's models.fsqla_vX classes - no changes are required.
  For Mongo, a ListField can be directly used.
- CSRF - As mentioned above, it is now required that `FlaskWTF::CSRFProtect()`, if used, must be called PRIOR to initializing Flask-Security.
- json_encoder_cls - As mentioned above - Flask-Security initialization no longer accepts overriding the json_encoder class. If this is required,
  update to Flask >=2.2 and implement Flask's JSONProvider interface.

For templates:

- Pretty much every template was modified to replace <p> with <div class=xx> to make
  styling possible and to make more complex forms more readable.
- Many forms had places where things weren't properly localizable - that has (hopefully) been fixed.
- The ``us_setup.html`` template was modified to add ability to delete an existing set up method.

DB Migration
~~~~~~~~~~~~

To use the new WebAuthn feature a new table and two new columns in the User model are required.
To ease updates - Flask-Security will automatically create a fs_webauthn_user_handle
upon first use for existing users.
If you are using Alembic the schema migration is easy::

    op.add_column('user', sa.Column('fs_webauthn_user_handle', sa.String(length=64), nullable=True, unique=True))


If you want to allow for empty passwords as part of registration then set :py:data:`SECURITY_PASSWORD_REQUIRED` to ``False``.
In addition you need to change your DB schema to allow the ``password`` field to be nullable.

Version 4.1.5
-------------

Released July 28, 2022

Fixes
+++++
- (:pr:`644`) Fix test and other failures with newer Flask-Login/Werkzeug versions.

Version 4.1.4
-------------

Released April 19, 2022

Fixes
+++++
- (:issue:`594`) Fix test failures with newer Flask versions.

Version 4.1.3
-------------

Released March 2, 2022

Fixes
+++++
- (:issue:`581`) Fix bug when attempting to disable register_blueprint. (halali)
- (:pr:`539`) Fix example documentation re: generating localized messages. (kazuhei2)
- (:pr:`546`) Make roles joinedload compatible with SQLAlchemy 2.0. (keats)
- (:pr:`586`) Ship py.typed as part of package.
- (:issue:`580`) Improve documentation around use of bleach and include in common install extra.

Version 4.1.2
-------------

Released September 22, 2021

Fixes
+++++
- (:issue:`526`) default_reauthn_handler doesn't honor SECURITY_URL_PREFIX
- (:pr:`528`) Improve German translations (sr-verde)
- (:pr:`527`) Fix two-factor sample code (djpnewton)

Version 4.1.1
--------------

Released September 10, 2021

Fixes
+++++
- (:issue:`518`) Fix corner case where Security object was being reused in tests.
- (:issue:`512`) If USERNAME_ENABLE is set, change LoginForm field from EmailField
  to StringField. Also - dynamically add fields to Login and Registration forms
  rather than always having them - this made the RegistrationForm much simpler.
- (:issue:`516`) Improved username feature handling solved issue of always requiring
  bleach.
- (:issue:`513`) Improve documentation of default username validation.

Version 4.1.0
-------------

Released July 23, 2021

Features
++++++++
- (:issue:`474`) Add public API and CLI command to change a user's password.
- (:issue:`140`) Add type hints. Please note that many of the packages that flask-security
  depends on aren't typed yet - so there are likely errors in some of the types.
- (:issue:`466`) Add first-class support for using username for signing in.

Fixes
+++++
- (:issue:`483`) 4.0 doesn't accept 3.4 authentication tokens. (kuba-lilz)
- (:issue:`490`) Flask-Mail sender name can be a tuple. (hrishikeshrt)
- (:issue:`486`) Possible open redirect vulnerability.
- (:pr:`478`) Improve/update German translation. (sr-verde)
- (:issue:`488`) Improve handling of Babel packages.
- (:pr:`496`) Documentation improvements, distribution extras, fix single message
  override.
- (:issue:`497`) Improve cookie handling and default ``samesite`` to ``Strict``.

Backwards Compatibility Concerns
+++++++++++++++++++++++++++++++++
- (:pr:`488`) In 4.0.0, with the addition of Flask-Babel support, Flask-Security enforced that
  if it could import either Flask-Babel or Flask-BabelEx, that those modules had
  been initialized as proper Flask extensions. Prior to 4.0.0, just Flask-BabelEx
  was supported - and that didn't require any explicit initialization. Flask-Babel
  DOES require explicit initialization. However for some applications that don't
  completely control their environment (such as system pre-installed versions of
  python) this caused applications that didn't even want translation services to
  fail on startup. With this release, Flask-Security still attempts to import
  one or the other package - however if those modules are NOT initialized,
  Flask-Security will simply ignore them and no translations will occur.
- (:issue:`497`) The CSRF_COOKIE and TWO_FACTOR_VALIDITY cookie had their defaults
  changed to set ``samesite=Strict``. This follows the Flask-Security goal of
  making things more secure out-of-the-box.
- (:issue:`140`) Type hinting. For the most part this of course has no runtime effects.
  However, this required a fairly major overhaul of how Flask-Security is initialized in
  order to provide valid types for the many constructor attributes. There are no known
  compatability concerns - however initialization used to convert all arguments into kwargs
  then add those as attributes and merge with application constants. That no longer happens
  and it is possible that some corner cases don't behave precisely as they did before.

Version 4.0.1
-------------

Released April 2, 2021

Features
++++++++

Fixes
+++++
- (:issue:`461`) 4.0 doesn't accept 3.4 authentication tokens. (kuba-lilz)
- (:issue:`460`) 2-fa error: Failed to send code - improved documentation and debuggability.
- (:issue:`454`) 2-fa error: TypeError - fixed documentation.
- (:issue:`443`) Calling create user without any arguments - fixed underlying cause
  of translating form errors in the CLI.
- (:issue:`442`) Email validation confusion - added documentation.
- (:issue:`450`) Add documentation on how to override specific error messages.
- (:pr:`439`) Don't install global-scope tests. (mgorny)
- (:pr:`470`) Add note about updating DB using MySQL. (jugmac00)
- (:pr:`468`) Fix documentation - uia_phone_number should be uia_phone_mapper. (dvrg)
- (:pr:`457`) Improve chinese translations. (zxjlm)
- (:pr:`453`) Improve basque and spanish translations. (mmozos)
- (:pr:`448`) Add Afrikaans translations. (lonelyvikingmichael)
- (:pr:`467`) Add Blinker as explicit dependency, improve/fix celery usage docs,
  dont require pyqrcode unless authenticator configured, improve SMS configuration
  variables documentation.



Version 4.0.0
-------------

Released January 26, 2021

**PLEASE READ CHANGE NOTES CAREFULLY - THERE ARE LIKELY REQUIRED CHANGES YOU WILL HAVE TO MAKE TO EVEN START YOUR APPLICATION WITH 4.0**

Start Here
+++++++++++
- Your UserModel must contain ``fs_uniquifier``
- Either uninstall Flask-BabelEx (if you don't need translations) or add either Flask-Babel (>=2.0) or Flask-BabelEx to your
  dependencies AND be sure to initialize it in your app.
- Add Flask-Mail to your dependencies.
- If you have unicode emails or passwords read change notes below.

Version 4.0.0rc2
----------------

Released January 18, 2021

Features & Cleanup
+++++++++++++++++++
- Removal of python 2.7 and <3.6 support
- Removal of token caching feature (a relatively new feature that had some systemic issues)
- (:pr:`328`) Remove dependence on Flask-Mail and refactor.
- (:pr:`335`) Remove two-factor `/tf-confirm` endpoint and use generic `freshness` mechanism.
- (:pr:`336`) Remove ``SECURITY_BACKWARDS_COMPAT_AUTH_TOKEN_INVALID(ATE)``. In addition to
  not making sense - the documentation has never been correct.
- (:pr:`339`) Require ``fs_uniquifier`` in the UserModel and stop using/referencing the UserModel
  primary key.
- (:pr:`349`) Change ``SECURITY_USER_IDENTITY_ATTRIBUTES`` configuration variable semantics.
- Remove (all?) requirements around having an 'email' column in the UserModel. API change -
  JSON SPA redirects used to always include a query param 'email=xx'. While that is still sent
  (if and only if) the UserModel contains an 'email' columns, a new query param 'identity' is returned
  which returns the value of :meth:`.UserMixin.calc_username()`.
- (:pr:`382`) Improvements and documentation for two-factor authentication.
- (:pr:`394`) Add support for email validation and normalization (see :class:`.MailUtil`).
- (:issue:`231`) Normalize unicode passwords (see :class:`.PasswordUtil`).
- (:issue:`391`) Option to redirect to `/confirm` if user hits an endpoint that requires
  confirmation. New option :py:data:`SECURITY_REQUIRES_CONFIRMATION_ERROR_VIEW` which if set and the user
  hits the `/login`, `/reset`, or `/us-signin` endpoint, and they require confirmation the response will be a redirect. (SnaKyEyeS)
- (:issue:`366`) Allow redirects on sub-domains. Please see :py:data:`SECURITY_REDIRECT_ALLOW_SUBDOMAINS`. (willcroft)
- (:pr:`376`) Have POST redirects default to Flask's ``APPLICATION_ROOT``. Previously the default configuration was ``/``.
  Now it first looks at Flask's `APPLICATION_ROOT` configuration and uses that (which also by default is ``/``. (tysonholub)
- (:pr:`401`) Add 2FA Validity Window so an application can configure how often the second factor has to be entered. (baurt)
- (:pr:`403`) Add HTML5 Email input types to email fields. This has some backwards compatibility concerns outlined below. (drola)
- (:pr:`413`) Add hy_AM translations. (rudolfamirjanyan)
- (:pr:`410`) Add Basque and fix Spanish translations. (mmozos)
- (:pr:`408`) Polish translations. (kamil559)
- (:pr:`390`) Update ru_RU translations. (TitaniumHocker)

Fixed
+++++
- (:issue:`389`) Fixes for translations. First - email subjects were never being translated. Second, converted
  all templates to use _fsdomain(xx) rather than _(xx) so that they get translated regardless of the app's domain.
- (:issue:`381`) Support Flask-Babel 2.0 which has backported Domain support. Flask-Security now supports
  Flask-Babel (>=2.00), Flask-BabelEx, as well as no translation support. Please see backwards compatibility notes below.
- (:pr:`352`) Fix issue with adding/deleting permissions - all mutating methods must be at the datastore layer so that
  db.put() can be called. Added :meth:`.UserDatastore.add_permissions_to_role` and :meth:`.UserDatastore.remove_permissions_from_role`.
  The methods `.RoleMixin.add_permissions` and `.RoleMixin.remove_permissions` have been deprecated.
- (:issue:`395`) Provide ability to change table names for User and Role tables in the fsqla model.
- (:issue:`338`) All sessions are invalidated when a user changes or resets their password. This is accomplished by
  changing the user's `fs_uniquifier`. The user is automatically re-logged in (and a new session
  created) after a successful change operation.
- (:issue:`418`) Two-factor (and to a lesser extent unified sign in) QRcode fetching wasn't protected via CSRF. The
  fix makes things secure and simpler (always good); however read below for compatibility concerns. In addition, the elements that make up the QRcode (key, username, issuer) area also made available to the form
  and returned as part of the JSON return value - this allows for manual or other ways to initialize the authenticator
  app.
- (:issue:`421`) GET on `/login` and `/change` could return the callers authentication_token. This is a security
  concern since GETs don't have CSRF protection. This bug was introduced in 3.3.0.

Backwards Compatibility Concerns
+++++++++++++++++++++++++++++++++
- (:pr:`328`) Remove dependence on Flask-Mail and refactor. The ``send_mail_task`` and
  ``send_mail`` methods as part of Flask-Security initialization
  have been removed and replaced with a new :class:`.MailUtil` class.
  The utility method :func:`.send_mail` can still be used.
  If your application didn't use either of the deprecated methods, then the only change required
  is to add Flask-Mail to your package requirements (since Flask-Security no longer lists it).
  Please see the :ref:`emails_topic` for updated examples.

- (:pr:`335`) Convert two-factor setup flow to use the freshness feature rather than
  its own verify password endpoint. This COMPLETELY removes the ``/tf-confirm`` endpoint
  and associated form: ``two_factor_verify_password_form``. Now, when /tf-setup is invoked,
  the :meth:`flask_security.check_and_update_authn_fresh` is invoked, and if the current session isn't 'fresh'
  the caller will be redirected to a verify endpoint (either :py:data:`SECURITY_VERIFY_URL` or
  :py:data:`SECURITY_US_VERIFY_URL`). The simplest change would be to call ``/verify`` everywhere
  the application used to call ``/tf-confirm``.

- (:pr:`339`) Require ``fs_uniquifier``. In 3.3 the ``fs_uniquifier`` was added in the UserModel to fix
  the slow authentication token issue. In 3.4 the ``fs_uniquifier`` was used to implement Flask-Login's
  `Alternative Token` feature - thus decoupling the primary key (id) from any security context.
  All along, there have been a few issues with applications not wanting to use the name 'id' in their
  model, or wanting a different type for their primary key. With this change, Flask-Security no longer
  interprets or uses the UserModel primary key - just the ``fs_uniquifier`` field. See the changes section for 3.3
  for information on how to do the schema and data upgrades required to add this field. There is also an API change -
  the JSON response (via UserModel.get_security_payload()) returned the ``user.id`` field. With this change
  the default is an empty directory - override :meth:`.UserMixin.get_security_payload()` to return any portion of the UserModel you need.

- (:pr:`349`) :py:data:`SECURITY_USER_IDENTITY_ATTRIBUTES` has changed syntax and semantics. It now contains
  the combined information from the old ``SECURITY_USER_IDENTITY_ATTRIBUTES`` and the newly introduced in 3.4 :py:data:`SECURITY_USER_IDENTITY_MAPPINGS`.
  This enabled changing the underlying way we validate credentials in the login form and unified sign in form.
  In prior releases we simply tried to look up the form value as the PK of the UserModel - this often failed and then
  looped through the other ``SECURITY_USER_IDENTITY_ATTRIBUTES``. This had a history of issues, including many applications not
  wanting to have a standard PK for the user model. Now, using the mapping configuration, the UserModel attribute/column the input
  corresponds to is determined, then the UserModel is queried specifically for that *attribute:value* pair. If you application
  didn't change the variable, no modifications are required.

- (:pr:`354`) The :class:`flask_security.PhoneUtil` is now initialized as part of Flask-Security initialization rather than
  ``@app.before_first_request`` (since that broke the CLI). Since it isn't called in an application context, the *app* being initialized is
  passed as an argument to *__init__*.

- (:issue:`381`) When using Flask-Babel (>= 2.0) it is required that the application initialize Flask-Babel (e.g. Babel(app)).
  Flask-BabelEx would self-initialize so it didn't matter. Flask-Security will throw a run time error upon first request if Flask-Babel
  OR FLask-BabelEx
  is installed, but not initialized. Also, Flask-Security no longer has a dependency on either Flask-Babel or Flask-BabelEx - if neither
  are installed, it falls back to a dummy translation. *If your application expects translation services, it must specify the appropriate*
  *dependency AND initialize it.*

- (:pr:`394`) Email input is now normalized prior to being stored in the DB. Previously, it was validated, but the raw input
  was stored. Normalization and validation rely on the `email_validator <https://pypi.org/project/email-validator/>`_ package.
  The :class:`.MailUtil` class provides the interface for normalization and validation - allowing all this to be customized.
  If you have unicode local or domain parts - existing users may have difficulties logging in. Administratively you need to
  read each user record, normalize the email (see :class:`.MailUtil`), and write it back.

- (:issue:`381`) Passwords are now, by default, normalized using Python's unicodedata.normalize() method.
  The :py:data:`SECURITY_PASSWORD_NORMALIZE_FORM` defaults to "NKFD". This brings Flask-Security
  in line with the NIST recommendations outlined in `Memorized Secret Verifiers <https://pages.nist.gov/800-63-3/sp800-63b.html#sec5>`_
  If your users have unicode passwords
  they may have difficulty authenticating. You can turn off this normalization or have your users reset their passwords.
  Password normalization and validation has been encapsulated in a new :class:`.PasswordUtil` class. This replaces
  the method ``password_validator`` introduced in 3.4.0.

- (:pr:`403`) By default all forms that have an email as input now use the wtforms html5 ``EmailField``. For most applications this will
  make the user experience slightly nicer - especially for mobile devices. Some applications use the email form field for other
  identity attributes (such as username). If your application does this you will probably need to subclass ``LoginForm`` and change
  the email type back to StringField.

- (:issue:`338`) By default, both passwords and authentication tokens use the same attribute ``fs_uniquifier`` to
  uniquely identify the user. This means that if the user changes or resets their password, all authentication tokens
  also become invalid. This could be viewed as a feature or a bug. If this behavior isn't desired, add another
  uniquifier: ``fs_token_uniquifier`` to your UserModel and that will be used to generate authentication tokens.

- (:issue:`418`) Fix CSRF vulnerability w.r.t. getting QRcodes. Both two-factor and unified-signup had a separate
  GET endpoint to fetch the QRcode when setting up an authenticator app. GETS don't have any CSRF protection. Both
  of those endpoints have been completely removed, and the QRcode is embedded in a successful POST of the setup form.
  The changes to the templates are minimal and of course if you didn't override the template - there is no
  compatibility concern.

- (:issue:`421`) Fix CSRF vulnerability on `/login` and `/change` that could return the callers authentication token.
  Now, callers can only get the authentication token on successful POST calls.

Version 3.4.5
--------------

Released January 8, 2021

Security Vulnerability Fix.

Two CSRF vulnerabilities were reported: `qrcode`_ and `login`_. This release
fixes the more severe of the 2 - the `/login` vulnerability. The QRcode issue
has a much smaller risk profile since a) it is only for two-factor authentication
using an authenticator app b) the qrcode is only available during the time
the user is first setting up their authentication app.
The QRcode issue has been fixed in 4.0.

.. _qrcode: https://github.com/Flask-Middleware/flask-security/issues/418
.. _login: https://github.com/Flask-Middleware/flask-security/issues/421

Fixed
+++++

- (:issue:`421`) GET on `/login` and `/change` could return the callers authentication_token. This is a security
  concern since GETs don't have CSRF protection. This bug was introduced in 3.3.0.

Backwards Compatibility Concerns
++++++++++++++++++++++++++++++++

- (:issue:`421`) Fix CSRF vulnerability on `/login` and `/change` that could return the callers authentication token.
  Now, callers can only get the authentication token on successful POST calls.

Version 3.4.4
--------------

Released July 27, 2020

Bug/regression fixes.

Fixed
+++++

- (:issue:`359`) Basic Auth broken. When the unauthenticated handler was changed to provide a more
  uniform/consistent response - it broke using Basic Auth from a browser, since it always redirected rather than
  returning 401. Now, if the response headers contain  ``WWW-Authenticate``
  (which is set if ``basic`` @auth_required method is used), a 401 is returned. See below
  for backwards compatibility concerns.

- (:pr:`362`) As part of figuring out issue 359 - a redirect loop was found. In release 3.3.0 code was put
  in to redirect to :py:data:`SECURITY_POST_LOGIN_VIEW` when GET or POST was called and the caller was already authenticated. The
  method used would honor the request ``next`` query parameter. This could cause redirect loops. The pre-3.3.0 behavior
  of redirecting to :py:data:`SECURITY_POST_LOGIN_VIEW` and ignoring the ``next`` parameter has been restored.

- (:issue:`347`) Fix peewee. Turns out - due to lack of unit tests - peewee hasn't worked since
  'permissions' were added in 3.3. Furthermore, changes in 3.4 around get_id and alternative tokens also
  didn't work since peewee defines its own `get_id` method.

Compatibility Concerns
++++++++++++++++++++++

In 3.3.0, :meth:`flask_security.auth_required` was changed to add a default argument if none was given. The default
include all current methods - ``session``, ``token``, and ``basic``. However ``basic`` really isn't like the others
and requires that we send back a ``WWW-Authenticate`` header if authentication fails (and return a 401 and not redirect).
``basic`` has been removed from the default set and must once again be explicitly requested.

Version 3.4.3
-------------

Released June 12, 2020

Minor fixes for a regression and a couple other minor changes

Fixed
+++++

- (:issue:`340`) Fix regression where tf_phone_number was required, even if SMS wasn't configured.
- (:pr:`342`) Pick up some small documentation fixes from 4.0.0.

Version 3.4.2
-------------

Released May 2, 2020

Only change is to move repo to the Flask-Middleware github organization.

Version 3.4.1
--------------

Released April 22, 2020

Fix a bunch of bugs in new unified sign in along with a couple other major issues.

Fixed
+++++
- (:issue:`298`) Alternative ID feature ran afoul of postgres/psycopg2 finickiness.
- (:issue:`300`) JSON 401 responses had WWW-Authenticate Header attached - that caused
  browsers to pop up their own login/password form. Not what applications want.
- (:issue:`280`) Allow admin/api to setup TFA (and unified sign in) out of band.
  Please see :meth:`.UserDatastore.tf_set`, :meth:`.UserDatastore.tf_reset`,
  :meth:`.UserDatastore.us_set`, :meth:`.UserDatastore.us_reset` and
  :meth:`.UserDatastore.reset_user_access`.
- (:pr:`305`) We used form._errors which wasn't very pythonic, and it was
  removed in WTForms 2.3.0.
- (:pr:`310`) WTForms 2.3.0 made email_validator optional - we need it.


Version 3.4.0
-------------

Released March 31, 2020

Features
++++++++
- (:pr:`257`) Support a unified sign in feature. Please see :ref:`unified-sign-in`.
- (:pr:`265`) Add phone number validation class. This is used in both unified sign in
  as well as two-factor when using ``sms``.
- (:pr:`274`) Add support for 'freshness' of caller's authentication. This permits endpoints
  to be additionally protected by ensuring a recent authentication.
- (:issue:`99`, :issue:`195`) Support pluggable password validators. Provide a default
  validator that offers complexity and breached support.
- (:issue:`266`) Provide interface to two-factor send_token so that applications
  can provide error mitigation. Defaults to returning errors if can't send the verification code.
- (:pr:`247`) Updated all-inclusive data models (fsqlaV2). Add fields necessary for the new unified sign in feature
  and changed 'username' to be unique (but not required).
- (:pr:`245`) Use fs_uniquifier as the default Flask-Login 'alternative token'. Basically
  this means that changing the fs_uniquifier will cause outstanding auth tokens, session and remember me
  cookies to be invalidated. So if an account gets compromised, an admin can easily stop access. Prior to this
  cookies were storing the 'id' which is the user's primary key - difficult to change! (kishi85)

Fixed
+++++
- (:issue:`273`) Don't allow reset password for accounts that are disabled.
- (:issue:`282`) Add configuration that disallows GET for logout. Allowing GET can
  cause some denial of service issues. The default still allows GET for backwards
  compatibility. (kantorii)
- (:issue:`258`) Reset password wasn't integrated into the two-factor feature and therefore
  two-factor auth could be bypassed.
- (:issue:`254`) Allow lists and sets as underlying permissions. (pffs)
- (:issue:`251`) Allow a registration form to have additional fields that aren't part of the user model
  that are just passed to the user_registered.send signal, where the application can perform arbitrary
  additional actions required during registration. (kuba-lilz)
- (:issue:`249`) Add configuration to disable the 'role-joining' optimization for SQLAlchemy. (pffs)
- (:issue:`238`) Fix more issues with atomically setting the new TOTP secret when setting up two-factor. (kishi85)
- (:pr:`240`) Fix Quart Compatibility. (ristellise)
- (:issue:`232`) CSRF Cookie not being set when using 'Remember Me' cookie to re-sign in. (kishi85)
- (:issue:`229`) Two-factor enabled accounts didn't work with the Remember Me feature. (kishi85)

As part of adding unified sign in, there were many similarities with two-factor.
Some refactoring was done to unify naming, configuration variables etc.
It should all be backwards compatible.

- In TWO_FACTOR_ENABLED_METHODS "mail" was changed to "email". "mail" will still
  be honored if already stored in DB. Also "google_authenticator" is now just "authenticator".
- TWO_FACTOR_SECRET, TWO_FACTOR_URI_SERVICE_NAME, TWO_FACTOR_SMS_SERVICE, and TWO_FACTOR_SMS_SERVICE_CONFIG
  have all been deprecated in favor of names that are the same for two-factor and unified sign in.

Other changes with possible backwards compatibility issues:

- ``/tf-setup`` never did any phone number validation. Now it does.
- ``two_factor_setup.html`` template - the chosen_method check was changed to ``email``.
  If you have your own custom template - be sure make that change.

Version 3.3.3
-------------

Released February 11, 2020

Minor changes required to work with latest released Werkzeug and Flask-Login.

Version 3.3.2
-------------

Released December 7, 2019

- (:issue:`215`) Fixed 2FA totp secret regeneration bug (kishi85)
- (:issue:`172`) Fixed 'next' redirect error in login view
- (:issue:`221`) Fixed regressions in login view when already authenticated user
  again does a GET or POST.
- (:issue:`219`) Added example code for unit testing FS protected routes.
- (:issue:`223`) Integrated two-factor auth into registration and confirmation.

Thanks to kuba-lilz and kishi85 for finding and providing detailed issue reports.

In Flask-Security 3.3.0 the login view was changed to allow already authenticated
users to access the view. Prior to 3.3.0, the login view was protected with
@anonymous_user_required - so any access (via GET or POST) would simply redirect
the user to the ``POST_LOGIN_VIEW``. With the 3.3.0 changes, both GET and POST
behaved oddly. GET simply returned the login template, and POST attempted to
log out the current user, and log in the new user. This was problematic since
this couldn't possibly work with CSRF.
The old behavior has been restored, with the subtle change that older Flask-Security
releases did not look at "next" in the form or request for the redirect,
and now, all redirects from the login view will honor "next".

Version 3.3.1
-------------

Released November 16, 2019

- (:pr:`197`) Add `Quart <https://gitlab.com/pgjones/quart/>`_ compatibility (Ristellise)
- (:pr:`194`) Add Python 3.8 support into CI (jdevera)
- (:pr:`196`) Improve docs around Single Page Applications and React (acidjunk)
- (:issue:`201`) fsqla model was added to __init__.py making Sqlalchemy a required package.
  That is wrong and has been removed. Applications must now explicitly import from ``flask_security.models``
- (:pr:`204`) Fix/improve examples and quickstart to show one MUST call hash_password() when
  creating users programmatically. Also show real SECRET_KEYs and PASSWORD_SALTs and how to generate them.
- (:pr:`209`) Add argon2 as an allowable password hash.
- (:pr:`210`) Improve integration with Flask-Admin. Actually - this PR improves localization support
  by adding a method ``_fsdomain`` to jinja2's global environment. Added documentation
  around localization.


Version 3.3.0
-------------

Released September 26, 2019

**There are several default behavior changes that might break existing applications.
Most have configuration variables that restore prior behavior**.

**If you use Authentication Tokens (rather than session cookies) you MUST make a (small) change.
Please see below for details.**

- (:pr:`120`) Native support for Permissions as part of Roles. Endpoints can be
  protected via permissions that are evaluated based on role(s) that the user has.
- (:issue:`126`, :issue:`93`, :issue:`96`) Revamp entire CSRF handling. This adds support for Single Page Applications
  and having CSRF protection for browser(session) authentication but ignored for
  token based authentication. Add extensive documentation about all the options.
- (:issue:`156`) Token authentication is slow. Please see below for details on how to enable a new, fast implementation.
- (:issue:`130`) Enable applications to provide their own :meth:`.render_json` method so that they can create
  unified API responses.
- (:issue:`121`) Unauthorized callback not quite right. Split into 2 different callbacks - one for
  unauthorized and one for unauthenticated. Made default unauthenticated handler use Flask-Login's unauthenticated
  method to make everything uniform. Extensive documentation added. `.Security.unauthorized_callback` has been deprecated.
- (:pr:`120`) Add complete User and Role model mixins that support all features. Modify tests and Quickstart documentation
  to show how to use these. Please see :ref:`responsetopic` for details.
- Improve documentation for :meth:`.UserDatastore.create_user` to make clear that hashed password
  should be passed in.
- Improve documentation for :class:`.UserDatastore` and :func:`.verify_and_update_password`
  to make clear that caller must commit changes to DB if using a session based datastore.
- (:issue:`122`) Clarify when to use ``confirm_register_form`` rather than ``register_form``.
- Fix bug in 2FA that didn't commit DB after using `verify_and_update_password`.
- Fix bug(s) in UserDatastore where changes to user ``active`` flag weren't being added to DB.
- (:issue:`127`) JSON response was failing due to LazyStrings in error response.
- (:issue:`117`) Making a user inactive should stop all access immediately.
- (:issue:`134`) Confirmation token can no longer be reused. Added
  *SECURITY_AUTO_LOGIN_AFTER_CONFIRM* option for applications that don't want the user
  to be automatically logged in after confirmation (defaults to True - existing behavior).
- (:issue:`159`) The ``/register`` endpoint returned the Authentication Token even though
  confirmation was required. This was a huge security hole - it has been fixed.
- (:issue:`160`) The 2FA totp_secret would be regenerated upon submission, making QRCode not work. (malware-watch)
- (:issue:`166`) `default_render_json` uses ``flask.make_response`` and forces the Content-Type to JSON for generating the response (koekie)
- (:issue:`166`) *SECURITY_MSG_UNAUTHENTICATED* added to the configuration.
- (:pr:`168`) When using the @auth_required or @auth_token_required decorators, the token
  would be verified twice, and the DB would be queried twice for the user. Given how slow
  token verification is - this was a significant issue. That has been fixed.
- (:issue:`84`) The :func:`.anonymous_user_required` was not JSON friendly - always
  performing a redirect. Now, if the request 'wants' a JSON response - it will receive a 400 with an error
  message defined by *SECURITY_MSG_ANONYMOUS_USER_REQUIRED*.
- (:pr:`145`) Improve 2FA templates to that they can be localized. (taavie)
- (:issue:`173`) *SECURITY_UNAUTHORIZED_VIEW* didn't accept a url (just an endpoint). All other view
  configurations did. That has been fixed.

Possible compatibility issues
+++++++++++++++++++++++++++++

- (:pr:`164`) In prior releases, the Authentication Token was returned as part of the JSON response to each
  successful call to `/login`, `/change`, or `/reset/{token}` API call. This is not a great idea since
  for browser-based UIs that used JSON request/response, and used session based authentication - they would
  be sent this token - even though it was likely ignored. Since these tokens by default have no expiration time
  this exposed a needless security hole. The new default behavior is to ONLY return the Authentication Token from those APIs
  if the query param ``include_auth_token`` is added to the request. Prior behavior can be restored by setting
  the *SECURITY_BACKWARDS_COMPAT_AUTH_TOKEN* configuration variable.

- (:pr:`120`) :class:`.RoleMixin` now has a method :meth:`.get_permissions` which is called as part
  each request to add Permissions to the authenticated user. It checks if the RoleModel
  has a property ``permissions`` and assumes it is a comma separated string of permissions.
  If your model already has such a property this will likely fail. You need to override :meth:`.get_permissions`
  and simply return an emtpy set.

- (:issue:`121`) Changes the default (failure) behavior for views protected with @auth_required, @token_auth_required,
  or @http_auth_required. Before, a 401 was returned with some stock html. Now, Flask-Login.unauthorized() is
  called (the same as @login_required does) - which by default redirects to a login page/view. If you had provided your own
  `.Security.unauthorized_callback` there are no changes - that will still be called first. The old default
  behavior can be restored by setting *SECURITY_BACKWARDS_COMPAT_UNAUTHN* to True. Please see :ref:`responsetopic` for details.

- (:issue:`127`) Fix for LazyStrings in json error response. The fix for this has Flask-Security registering
  its own JsonEncoder on its blueprint. If you registered your own JsonEncoder for your app - it will no
  longer be called when serializing responses to Flask-Security endpoints. You can register your JsonEncoder
  on Flask-Security's blueprint by sending it as `json_encoder_cls` as part of initialization. Be aware that your
  JsonEncoder needs to handle LazyStrings (see speaklater).

- (:issue:`84`) Prior to this fix - anytime the decorator :func:`.anonymous_user_required` failed, it caused a redirect to
  the post_login_view. Now, if the caller wanted a JSON response, it will return a 400.

- (:issue:`156`) Faster Authentication Token introduced the following non-backwards compatible behavior change:

    * Since the old Authentication Token algorithm used the (hashed) user's password, those tokens would be invalidated
      whenever the user changed their password. This is not likely to be what most users expect. Since the new
      Authentication Token algorithm doesn't refer to the user's password, changing the user's password won't invalidate
      outstanding Authentication Tokens. The method :meth:`.UserDatastore.set_uniquifier` can be used by an administrator
      to change a user's ``fs_uniquifier`` - but nothing the user themselves can do to invalidate their Authentication Tokens.
      Setting the *SECURITY_BACKWARDS_COMPAT_AUTH_TOKEN_INVALIDATE* configuration variable will cause the user's ``fs_uniquifier`` to
      be changed when they change their password, thus restoring prior behavior.


New fast authentication token implementation
++++++++++++++++++++++++++++++++++++++++++++
Current auth tokens are slow because they use the user's password (hashed) as a uniquifier (the
user id isn't really enough since it might be reused). This requires checking the (hashed) password against
what is in the token on EVERY request - however hashing is (on purpose) slow. So this can add almost a whole second
to every request.

To solve this, a new attribute in the User model was added - ``fs_uniquifier``. If this is present in your
User model, then it will be used instead of the password for ensuring the token corresponds to the correct user.
This is very fast. If that attribute is NOT present - then the behavior falls back to the existing (slow) method.


DB Migration
~~~~~~~~~~~~

To use the new UserModel mixins or to add the column ``user.fs_uniquifier`` to speed up token
authentication, a schema AND data migration needs to happen. If you are using Alembic the schema migration is
easy - but you need to add ``fs_uniquifier`` values to all your existing data. You can
add code like this to your migrations::update method::

    # be sure to MODIFY this line to make nullable=True:
    op.add_column('user', sa.Column('fs_uniquifier', sa.String(length=64), nullable=True))

    # update existing rows with unique fs_uniquifier
    import uuid
    user_table = sa.Table('user', sa.MetaData(), sa.Column('id', sa.Integer, primary_key=True),
                          sa.Column('fs_uniquifier', sa.String))
    conn = op.get_bind()
    for row in conn.execute(sa.select([user_table.c.id])):
        conn.execute(user_table.update().values(fs_uniquifier=uuid.uuid4().hex).where(user_table.c.id == row['id']))

    # finally - set nullable to false
    op.alter_column('user', 'fs_uniquifier', nullable=False)

    # for MySQL the previous line has to be replaced with...
    # op.alter_column('user', 'fs_uniquifier', existing_type=sa.String(length=64), nullable=False)


Version 3.2.0
-------------

Released June 26th 2019

- (:pr:`80`) Support caching of authentication token (eregnier `opr #839 <https://github.com/mattupstate/flask-security/pull/839>`_).
  This adds a new configuration variable *SECURITY_USE_VERIFY_PASSWORD_CACHE*
  which enables a cache (with configurable TTL) for authentication tokens.
  This is a big performance boost for those accessing Flask-Security via token
  as opposed to session.
- (:pr:`81`) Support for JSON/Single-Page-Application. This completes support
  for non-form based access to Flask-Security. See PR for details. (jwag956)
- (:pr:`79` Add POST logout to enhance JSON usage (jwag956).
- (:pr:`73`) Fix get_user for various DBs (jwag956).
  This is a more complete fix than in opr #633.
- (:pr:`78`, :pr:`103`) Add formal openapi API spec (jwag956).
- (:pr:`86`, :pr:`94`, :pr:`98`, :pr:`101`, :pr:`104`) Add Two-factor authentication (opr #842) (baurt, jwag956).
- (:issue:`108`) Fix form field label translations (jwag956)
- (:issue:`115`) Fix form error message translations (upstream #801) (jwag956)
- (:issue:`87`) Convert entire repo to Black (baurt)

Version 3.1.0
-------------

Released never

- (:pr:`53`) Use Security.render_template in mails too (noirbizarre `opr #487 <https://github.com/mattupstate/flask-security/pull/487>`_)
- (:pr:`56`) Optimize DB accesses by using an SQL JOIN when retrieving a user. (nfvs `opr #679 <https://github.com/mattupstate/flask-security/pull/679>`_)
- (:pr:`57`) Add base template to security templates (grihabor `opr #697 <https://github.com/mattupstate/flask-security/pull/697>`_)
- (:pr:`73`) datastore: get user by numeric identity attribute (jirikuncar `opr #633 <https://github.com/mattupstate/flask-security/pull/633>`_)
- (:pr:`58`) bugfix: support application factory pattern (briancappello `opr #703 <https://github.com/mattupstate/flask-security/pull/703>`_)
- (:pr:`60`) Make SECURITY_PASSWORD_SINGLE_HASH a list of scheme ignoring double hash (noirbizarre `opr #714 <https://github.com/mattupstate/flask-security/pull/714>`_)
- (:pr:`61`) Allow custom login_manager to be passed in to Flask-Security (jaza `opr #717 <https://github.com/mattupstate/flask-security/pull/717>`_)
- (:pr:`62`) Docs for OAauth2-based custom login manager (jaza `opr #727 <https://github.com/mattupstate/flask-security/pull/727>`_)
- (:pr:`63`) core: make the User model check the password (mklassen `opr #779 <https://github.com/mattupstate/flask-security/pull/779>`_)
- (:pr:`64`) Customizable send_mail (abulte `opr #730 <https://github.com/mattupstate/flask-security/pull/730>`_)
- (:pr:`68`) core: fix default for UNAUTHORIZED_VIEW (jirijunkar `opr #726 <https://github.com/mattupstate/flask-security/pull/726>`_)

These should all be backwards compatible.

Possible compatibility issues:

- #487 - prior to this, render_template() was overridable for views, but not
  emails. If anyone actually relied on this behavior, this has changed.
- #703 - get factory pattern working again. There was a very complex dance between
  Security() instantiation and init_app regarding kwargs. This has been rationalized (hopefully).
- #679 - SqlAlchemy SQL improvement. It is possible you will get the following error::

    Got exception during processing: <class 'sqlalchemy.exc.InvalidRequestError'> -
    'User.roles' does not support object population - eager loading cannot be applied.

  This is likely solvable by removing ``lazy='dynamic'`` from your Role definition.


Performance improvements:

- #679 - for sqlalchemy, for each request, there would be 2 DB accesses - now
  there is one.

Testing:
For datastores operations, Sqlalchemy, peewee, pony were all tested against sqlite,
postgres, and mysql real databases.


Version 3.0.2
-------------

Released April 30th 2019

- (opr #439) HTTP Auth respects SECURITY_USER_IDENTITY_ATTRIBUTES (pnpnpn)
- (opr #660) csrf_enabled` deprecation fix (abulte)
- (opr #671) Fix referrer loop in _get_unauthorized_view(). (nfvs)
- (opr #675) Fix AttributeError in _request_loader (sbagan)
- (opr #676) Fix timing attack on login form (cript0nauta)
- (opr #683) Close db connection after running tests (reambus)
- (opr #691) docs: add password salt to SQLAlchemy app example (KshitijKarthick)
- (opr #692) utils: fix incorrect email sender type (switowski)
- (opr #696) Fixed broken Click link (williamhatcher)
- (opr #722) Fix password recovery confirmation on deleted user (kesara)
- (opr #747) Update login_user.html (rickwest)
- (opr #748) i18n: configurable the dirname domain (escudero)
- (opr #835) adds relevant user to reset password form for validation purposes (fuhrysteve)

These are bug fixes and a couple very small additions.
No change in behavior and no new functionality.
'opr#' is the original pull request from https://github.com/mattupstate/flask-security

Version 3.0.1
--------------

Released April 28th 2019

- Support 3.7 as part of CI
- Rebrand to this forked repo
- (#15) Build docs and translations as part of CI
- (#17) Move to msgcheck from pytest-translations
- (opr #669) Fix for Read the Docs (jirikuncar)
- (opr #710) Spanish translation (maukoquiroga)
- (opr #712) i18n: improvements of German translations (eseifert)
- (opr #713) i18n: add Portuguese (Brazilian) translation (dinorox)
- (opr #719) docs: fix anchor links and typos (kesara)
- (opr #751) i18n: fix missing space (abulte)
- (opr #762) docs: fixed proxy import (lsmith)
- (opr #767) Update customizing.rst (allanice001)
- (opr #776) i18n: add Portuguese (Portugal) translation (micael-grilo)
- (opr #791) Fix documentation for mattupstate#781 (fmerges)
- (opr #796) Chinese translations (Steinkuo)
- (opr #808) Clarify that a commit is needed after login_user (christophertull)
- (opr #823) Add Turkish translation (Admicos)
- (opr #831) Catalan translation (miceno)

These are all documentation and i18n changes - NO code changes. All except the last 3 were accepted and reviewed by
the original Flask-Security team.
Thanks as always to all the contributors.

Version 3.0.0
-------------

Released May 29th 2017

- Fixed a bug when user clicking confirmation link after confirmation
  and expiration causes confirmation email to resend. (see #556)
- Added support for I18N.
- Added options `SECURITY_EMAIL_PLAINTEXT` and `SECURITY_EMAIL_HTML`
  for sending respectively plaintext and HTML version of email.
- Fixed validation when missing login information.
- Fixed condition for token extraction from JSON body.
- Better support for universal bdist wheel.
- Added port of CLI using Click configurable using options
  `SECURITY_CLI_USERS_NAME` and `SECURITY_CLI_ROLES_NAME`.
- Added new configuration option `SECURITY_DATETIME_FACTORY` which can
  be used to force default timezone for newly created datetimes.
  (see mattupstate/flask-security#466)
- Better IP tracking if using Flask 0.12.
- Renamed deprecated Flask-WFT base form class.
- Added tests for custom forms configured using app config.
- Added validation and tests for next argument in logout endpoint. (see #499)
- Bumped minimal required versions of several packages.
- Extended test matric on Travis CI for minimal and released package versions.
- Added of .editorconfig and forced tests for code style.
- Fixed a security bug when validating a confirmation token, also checks
  if the email that the token was created with matches the user's current email.
- Replaced token loader with request loader.
- Changed trackable behavior of `login_user` when IP can not be detected from a request from 'untrackable' to `None` value.
- Use ProxyFix instead of inspecting X-Forwarded-For header.
- Fix identical problem with app as with datastore.
- Removed always-failing assertion.
- Fixed failure of init_app to set self.datastore.
- Changed to new style flask imports.
- Added proper error code when returning JSON response.
- Changed obsolete Required validator from WTForms to DataRequired. Bumped Flask-WTF to 0.13.
- Fixed missing `SECURITY_SUBDOMAIN` in config docs.
- Added cascade delete in PeeweeDatastore.
- Added notes to docs about `SECURITY_USER_IDENTITY_ATTRIBUTES`.
- Inspect value of `SECURITY_UNAUTHORIZED_VIEW`.
- Send password reset instructions if an attempt has expired.
- Added "Forgot password?" link to LoginForm description.
- Upgraded passlib, and removed bcrypt version restriction.
- Removed a duplicate line ('retype_password': 'Retype Password') in forms.py.
- Various documentation improvement.

Version 1.7.5
-------------

Released December 2nd 2015

- Added `SECURITY_TOKEN_MAX_AGE` configuration setting
- Fixed calls to `SQLAlchemyUserDatastore.get_user(None)` (this now returns `False` instead of raising a `TypeError`
- Fixed URL generation adding extra slashes in some cases (see GitHub #343)
- Fixed handling of trackable IP addresses when the `X-Forwarded-For` header contains multiple values
- Include WWW-Authenticate headers in `@auth_required` authentication checks
- Fixed error when `check_token` function is used with a json list
- Added support for custom `AnonymousUser` classes
- Restricted `forgot_password` endpoint to anonymous users
- Allowed unauthorized callback to be overridden
- Fixed issue where passwords cannot be reset if currently set to `None`
- Ensured that password reset tokens are invalidated after use
- Updated `is_authenticated` and `is_active` functions to support Flask-Login changes
- Various documentation improvements


Version 1.7.4
-------------

Released October 13th 2014

- Fixed a bug related to changing existing passwords from plaintext to hashed
- Fixed a bug in form validation that did not enforce case insensitivity
- Fixed a bug with validating redirects


Version 1.7.3
-------------

Released June 10th 2014

- Fixed a bug where redirection to `SECURITY_POST_LOGIN_VIEW` was not respected
- Fixed string encoding in various places to be friendly to unicode
- Now using `werkzeug.security.safe_str_cmp` to check tokens
- Removed user information from JSON output on `/reset` responses
- Added Python 3.4 support


Version 1.7.2
-------------

Released May 6th 2014

- Updated IP tracking to check for `X-Forwarded-For` header
- Fixed a bug regarding the re-hashing of passwords with a new algorithm
- Fixed a bug regarding the `password_changed` signal.


Version 1.7.1
-------------

Released January 14th 2014

- Fixed a bug where passwords would fail to verify when specifying a password hash algorithm


Version 1.7.0
-------------

Released January 10th 2014

- Python 3.3 support!
- Dependency updates
- Fixed a bug when `SECURITY_LOGIN_WITHOUT_CONFIRMATION = True` did not allow users to log in
- Added `SECURITY_SEND_PASSWORD_RESET_NOTICE_EMAIL` configuration option to optionally send password reset notice emails
- Add documentation for `@security.send_mail_task`
- Move to `request.get_json` as `request.json` is now deprecated in Flask
- Fixed a bug when using AJAX to change a user's password
- Added documentation for select functions in the `flask_security.utils` module
- Fixed a bug in `flask_security.forms.NextFormMixin`
- Added `CHANGE_PASSWORD_TEMPLATE` configuration option to optionally specify a different change password template
- Added the ability to specify addtional fields on the user model to be used for identifying the user via the `USER_IDENTITY_ATTRIBUTES` configuration option
- An error is now shown if a user tries to change their password and the password is the same as before. The message can be customed with the `SECURITY_MSG_PASSWORD_IS_SAME` configuration option
- Fixed a bug in `MongoEngineUserDatastore` where user model would not be updated when using the `add_role_to_user` method
- Added `SECURITY_SEND_PASSWORD_CHANGE_EMAIL` configuration option to optionally disable password change email from being sent
- Fixed a bug in the `find_or_create_role` method of the PeeWee datastore
- Removed pypy tests
- Fixed some tests
- Include CHANGES and LICENSE in MANIFEST.in
- A bit of documentation cleanup
- A bit of code cleanup including removal of unnecessary utcnow call and simplification of get_max_age method


Version 1.6.9
-------------

Released August 20th 2013

- Fix bug in SQLAlchemy datastore's `get_user` function
- Fix bug in PeeWee datastore's `remove_role_from_user` function
- Fixed import error caused by new Flask-WTF release


Version 1.6.8
-------------

Released August 1st 2013

- Fixed bug with case sensitivity of email address during login
- Code cleanup regarding token_callback
- Ignore validation errors in find_user function for MongoEngineUserDatastore


Version 1.6.7
-------------

Released July 11th 2013

- Made password length form error message configurable
- Fixed email confirmation bug that prevented logged in users from confirming their email


Version 1.6.6
-------------

Released June 28th 2013

- Fixed dependency versions


Version 1.6.5
-------------

Released June 20th 2013

- Fixed bug in `flask.ext.security.confirmable.generate_confirmation_link`


Version 1.6.4
-------------

Released June 18th 2013

- Added `SECURITY_DEFAULT_REMEMBER_ME` configuration value to unify behavior between endpoints
- Fixed Flask-Login dependency problem
- Added optional `next` parameter to registration endpoint, similar to that of login


Version 1.6.3
-------------

Released May 8th 2013

- Fixed bug in regards to imports with latest version of MongoEngine


Version 1.6.2
-------------

Released April 4th 2013

- Fixed bug with http basic auth


Version 1.6.1
-------------

Released April 3rd 2013

- Fixed bug with signals


Version 1.6.0
-------------

Released March 13th 2013

- Added Flask-Pewee support
- Password hashing is now more flexible and can be changed to a different type at will
- Flask-Login messages are configurable
- AJAX requests must now send a CSRF token for security reasons
- Form messages are now configurable
- Forms can now be extended with more fields
- Added change password endpoint
- Added the user to the request context when successfully authenticated via http basic and token auth
- The Flask-Security blueprint subdomain is now configurable
- Redirects to other domains are now not allowed during requests that may redirect
- Template paths can be configured
- The welcome/register email can now optionally be sent to the user
- Passwords can now contain non-latin characters
- Fixed a bug when confirming an account but the account has been deleted


Version 1.5.4
-------------

Released January 6th 2013

- Fix bug in forms with `csrf_enabled` parameter not accounting attempts to login using JSON data


Version 1.5.3
-------------

Released December 23rd 2012

- Change dependency requirement

Version 1.5.2
-------------

Released December 11th 2012

- Fix a small bug in `flask_security.utils.login_user` method

Version 1.5.1
-------------

Released November 26th 2012

- Fixed bug with `next` form variable
- Added better documentation regarding Flask-Mail configuration
- Added ability to configure email subjects

Version 1.5.0
-------------

Released October 11th 2012

- Major release. Upgrading from previous versions will require a bit of work to
  accommodate API changes. See documentation for a list of new features and for
  help on how to upgrade.

Version 1.2.3
-------------

Released June 12th 2012

- Fixed a bug in the RoleMixin eq/ne functions

Version 1.2.2
-------------

Released April 27th 2012

- Fixed bug where `roles_required` and `roles_accepted` did not pass the next
  argument to the login view

Version 1.2.1
-------------

Released March 28th 2012

- Added optional user model mixin parameter for datastores
- Added CreateRoleCommand to available Flask-Script commands

Version 1.2.0
-------------

Released March 12th 2012

- Added configuration option `SECURITY_FLASH_MESSAGES` which can be set to a
  boolean value to specify if Flask-Security should flash messages or not.

Version 1.1.0
-------------

Initial release
