Flask-Security Changelog
========================

Here you can see the full list of changes between each Flask-Security release.

Version 3.4.0
-------------

Released TBD

- (:issue:`99`, :issue:`195`) Support pluggable password validators. Provide a default
  validator that offers complexity and breached support.

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
- (:issue:`121`) Unauthorization callback not quite right. Split into 2 different callbacks - one for
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


Version 3.2.0
-------------

Released June 26th 2019

- (opr #839) Support caching of authentication token (eregnier).
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

- (opr #487) Use Security.render_template in mails too (noirbizarre)
- (opr #679) Optimize DB accesses by using an SQL JOIN when retrieving a user. (nfvs)
- (opr #697) Add base template to security templates (grihabor)
- (opr #633) datastore: get user by numeric identity attribute (jirikuncar)
- (opr #703) bugfix: support application factory pattern (briancappello)
- (opr #714) Make SECURITY_PASSWORD_SINGLE_HASH a list of scheme ignoring double hash (noirbizarre )
- (opr #717) Allow custom login_manager to be passed in to Flask-Security (jaza)
- (opr #727) Docs for OAauth2-based custom login manager (jaza)
- (opr #779) core: make the User model check the password (mklassen)
- (opr #730) Customizable send_mail (abulte)
- (opr #726) core: fix default for UNAUTHORIZED_VIEW (jirijunkar)

These should all be backwards compatible.

Possible compatibility issues:

- #487 - prior to this, render_template() was overiddable for views, but not
  emails. If anyone actually relied on this behavior, this has changed.
- #703 - get factory pattern working again. There was a very complex dance between
  Security() instantiation and init_app regarding kwargs. This has been rationalized (hopefully).
- #679 - SqlAlchemy SQL improvement. It is possible you will get the following error::

    Got exception during processing: <class 'sqlalchemy.exc.InvalidRequestError'> -
    'User.roles' does not support object population - eager loading cannot be applied.

  This is likely solveable by removing ``lazy='dynamic'`` from your Role definition.


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
  for sending respecively plaintext and HTML version of email.
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
- Changed obsolette Required validator from WTForms to DataRequired. Bumped Flask-WTF to 0.13.
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
- Fixed a bug in form validation that did not enforce case insensivitiy
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
- Added `SECURITY_SEND_PASSWORD_RESET_NOTICE_EMAIL` configuraiton option to optionally send password reset notice emails
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
  accomodate API changes. See documentation for a list of new features and for
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
