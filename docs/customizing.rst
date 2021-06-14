Customizing
===========

Flask-Security bootstraps your application with various views for handling its
configured features to get you up and running as quickly as possible. However,
you'll probably want to change the way these views look to be more in line with
your application's visual design.


Views
-----

Flask-Security is packaged with a default template for each view it presents to
a user. Templates are located within a subfolder named ``security``. The
following is a list of view templates:

* `security/forgot_password.html`
* `security/login_user.html`
* `security/register_user.html`
* `security/reset_password.html`
* `security/change_password.html`
* `security/send_confirmation.html`
* `security/send_login.html`
* `security/verify.html`
* `security/two_factor_setup.html`
* `security/two_factor_verify_code.html`
* `security/us_signin.html`
* `security/us_setup.html`
* `security/us_verify.html`

Overriding these templates is simple:

1. Create a folder named ``security`` within your application's templates folder
2. Create a template with the same name for the template you wish to override

You can also specify custom template file paths in the :doc:`configuration <configuration>`.

Each template is passed a template context object that includes the following,
including the objects/values that are passed to the template by the main
Flask application context processor:

* ``<template_name>_form``: A form object for the view
* ``security``: The Flask-Security extension object

To add more values to the template context, you can specify a context processor
for all views or a specific view. For example::

    security = Security(app, user_datastore)

    # This processor is added to all templates
    @security.context_processor
    def security_context_processor():
        return dict(hello="world")

    # This processor is added to only the register view
    @security.register_context_processor
    def security_register_processor():
        return dict(something="else")

The following is a list of all the available context processor decorators:

* ``context_processor``: All views
* ``forgot_password_context_processor``: Forgot password view
* ``login_context_processor``: Login view
* ``register_context_processor``: Register view
* ``reset_password_context_processor``: Reset password view
* ``change_password_context_processor``: Change password view
* ``send_confirmation_context_processor``: Send confirmation view
* ``send_login_context_processor``: Send login view
* ``mail_context_processor``: Whenever an email will be sent
* ``tf_setup_context_processor``: Two factor setup view
* ``tf_token_validation_context_processor``: Two factor token validation view
* ``us_signin_context_processor``: Unified sign in view
* ``us_setup_context_processor``: Unified sign in setup view


Forms
-----

All forms can be overridden. For each form used, you can specify a
replacement class. This allows you to add extra fields to the
register form or override validators::

    from flask_security import RegisterForm
    from wtforms import StringField
    from wtforms.validators import DataRequired

    class ExtendedRegisterForm(RegisterForm):
        first_name = StringField('First Name', [DataRequired()])
        last_name = StringField('Last Name', [DataRequired()])

    security = Security(app, user_datastore,
             register_form=ExtendedRegisterForm)

For the ``register_form`` and ``confirm_register_form``, only fields that
exist in the user model are passed (as kwargs) to :meth:`.UserDatastore.create_user`.
Thus, in the above case, the ``first_name`` and ``last_name`` fields will only
be passed if the model looks like::

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(255), unique=True)
        password = db.Column(db.String(255))
        first_name = db.Column(db.String(255))
        last_name = db.Column(db.String(255))

The following is a list of all the available form overrides:

* ``login_form``: Login form
* ``confirm_register_form``: Confirmable register form
* ``register_form``: Register form
* ``forgot_password_form``: Forgot password form
* ``reset_password_form``: Reset password form
* ``change_password_form``: Change password form
* ``send_confirmation_form``: Send confirmation form
* ``passwordless_login_form``: Passwordless login form
* ``two_factor_verify_code_form``: Two-factor verify code form
* ``two_factor_setup_form``: Two-factor setup form
* ``two_factor_rescue_form``: Two-factor help user form
* ``us_signin_form``: Unified sign in form
* ``us_setup_form``: Unified sign in setup form
* ``us_setup_validate_form``: Unified sign in setup validation form

.. tip::
    Changing/extending the form class won't directly change how it is displayed.
    You need to ALSO provide your own template and explicitly adds the new fields you want displayed.

Localization
------------
All messages, form labels, and form strings are localizable. Flask-Security uses
`Flask-Babel <https://pypi.org/project/Flask-Babel/>`_ or
`Flask-BabelEx <https://pythonhosted.org/Flask-BabelEx/>`_ to manage its messages.

.. tip::
    Be sure to explicitly initialize your babel extension::

        import flask_babel

        flask_babel.Babel(app)

All translations are tagged with a domain, as specified by the configuration variable
``SECURITY_I18N_DOMAIN`` (default: "flask_security"). For messages and labels all this
works seamlessly.  For strings inside templates it is necessary to explicitly ask for
the "flask_security" domain, since your application itself might have its own domain.
Flask-Security places the method ``_fsdomain`` in jinja2's global environment and
uses that in all templates.
In order to reference a Flask-Security translation from ANY template (such as if you copied and
modified an existing security template) just use that method::

    {{ _fsdomain("Login") }}

Be aware that Flask-Security will validate and normalize email input using the
`email_validator <https://pypi.org/project/email-validator/>`_ package.
The normalized form is stored in the DB.

Overriding Messages
++++++++++++++++++++

It is possible to change one or more messages (either the original default english
and/or a specific translation). Adding the following to your app::

    app.config["SECURITY_MSG_INVALID_PASSWORD"] = ("Password no-worky", "error")

Will change the default message in english.

.. tip::
    The string messages themselves are a 'key' into the translation .po/.mo files.
    Do not pass in gettext('string') or lazy_gettext('string).

If you need translations then you
need to create your own ``translations`` directory and add the appropriate .po files
and compile them. Finally, add your translations directory path to the configuration.
In this example, create a file ``flask_security.po`` under a directory:
``translations/fr_FR/LC_MESSAGES`` (for french) with the following contents::

    msgid ""
    msgstr ""

    msgid "Password no-worky"
    msgstr "Passe - no-worky"


Then compile it with::

    pybabel compile -d translations/ -i translations/fr_FR/LC_MESSAGES/flask_security.po -l fr_FR

Finally add your translations directory to your configuration::

    app.config["SECURITY_I18N_DIRNAME"] = [pkg_resources.resource_filename("flask_security", "translations"), "translations"]

.. note::
    This only works when using Flask-Babel since Flask-BabelEx doesn't support a list of translation directories.

.. _emails_topic:

Emails
------

Flask-Security is also packaged with a default template for each email that it
may send. Templates are located within the subfolder named ``security/email``.
The following is a list of email templates:

* `security/email/confirmation_instructions.html`
* `security/email/confirmation_instructions.txt`
* `security/email/login_instructions.html`
* `security/email/login_instructions.txt`
* `security/email/reset_instructions.html`
* `security/email/reset_instructions.txt`
* `security/email/reset_notice.html`
* `security/email/reset_notice.txt`
* `security/email/change_notice.txt`
* `security/email/change_notice.html`
* `security/email/welcome.html`
* `security/email/welcome.txt`
* `security/email/two_factor_instructions.html`
* `security/email/two_factor_instructions.txt`
* `security/email/two_factor_rescue.html`
* `security/email/two_factor_rescue.txt`
* `security/email/us_instructions.html`
* `security/email/us_instructions.txt`

Overriding these templates is simple:

1. Create a folder named ``security`` within your application's templates folder
2. Create a folder named ``email`` within the ``security`` folder
3. Create a template with the same name for the template you wish to override

Each template is passed a template context object that includes values as described below.
In addition, the ``security`` object is always passed - you can for example render
any security configuration variable via ``security.lower_case_variable_name``
and don't include the prefix ``security_`` (e.g. ``{{ security.confirm_url }``)}.
If you require more values in the
templates, you can specify an email context processor with the
``mail_context_processor`` decorator. For example::

    security = Security(app, user_datastore)

    # This processor is added to all emails
    @security.mail_context_processor
    def security_mail_processor():
        return dict(hello="world")


There are many configuration variables associated with emails, and each template
will receive a slightly different context. The ``Gate Config`` column are configuration variables that if set
to ``False`` will bypass sending of the email (they all default to ``True``).
In most cases, in addition to an email being sent, a :ref:`Signal <signals_topic>` is sent.
The table below summarizes all this:

=============================   ================================   =============================================     ====================== ===============================
**Template Name**               **Gate Config**                    **Subject Config**                                **Context Vars**       **Signal Sent**
-----------------------------   --------------------------------   ---------------------------------------------     ---------------------- -------------------------------
welcome                         SECURITY_SEND_REGISTER_EMAIL       SECURITY_EMAIL_SUBJECT_REGISTER                   - user                 user_registered
                                                                                                                     - confirmation_link
                                                                                                                     - confirmation_token
confirmation_instructions       N/A                                SECURITY_EMAIL_SUBJECT_CONFIRM                    - user                 confirm_instructions_sent
                                                                                                                     - confirmation_link
                                                                                                                     - confirmation_token
login_instructions              N/A                                SECURITY_EMAIL_SUBJECT_PASSWORDLESS               - user                 login_instructions_sent
                                                                                                                     - login_link
                                                                                                                     - login_token
reset_instructions              SEND_PASSWORD_RESET_EMAIL          SECURITY_EMAIL_SUBJECT_PASSWORD_RESET             - user                 reset_password_instructions_sent
                                                                                                                     - reset_link
                                                                                                                     - reset_token
reset_notice                    SEND_PASSWORD_RESET_NOTICE_EMAIL   SECURITY_EMAIL_SUBJECT_PASSWORD_NOTICE            - user                 password_reset

change_notice                   SEND_PASSWORD_CHANGE_EMAIL         SECURITY_EMAIL_SUBJECT_PASSWORD_CHANGE_NOTICE     - user                 password_changed
two_factor_instructions         N/A                                SECURITY_EMAIL_SUBJECT_TWO_FACTOR                 - user                 tf_security_token_sent
                                                                                                                     - token
                                                                                                                     - username
two_factor_rescue               N/A                                SECURITY_EMAIL_SUBJECT_TWO_FACTOR_RESCUE          - user                 N/A
us_instructions                 N/A                                SECURITY_US_EMAIL_SUBJECT                         - user                 us_security_token_sent
                                                                                                                     - login_token
                                                                                                                     - login_link
                                                                                                                     - username
=============================   ================================   =============================================     ====================== ===============================

When sending an email, Flask-Security goes through the following steps:

  #. Calls the email context processor as described above

  #. Calls ``render_template`` (as configured at Flask-Security initialization time) with the
     context and template to produce a text and/or html version of the message

  #. Calls :meth:`.MailUtil.send_mail` with all the required parameters.

The default implementation of ``MailUtil.send_mail`` uses Flask-Mail to create and send the message.
By providing your own implementation, you can use any available python email handling package.

Email subjects are by default localized - see above section on Localization to learn how
to customize them.

Emails with Celery
++++++++++++++++++

Sometimes it makes sense to send emails via a task queue, such as `Celery`_.
This is supported by providing your own implementation of the :class:`.MailUtil` class::

    from flask_security import MailUtil
    class MyMailUtil(MailUtil):

        def send_mail(self, template, subject, recipient, sender, body, html, user, **kwargs):
            send_flask_mail.delay(
                subject=subject,
                sender=sender,
                recipients=[recipient],
                body=body,
                html=html,
            )

Then register your class as part of Flask-Security initialization::

    from flask import Flask
    from flask_mail import Mail, Message
    from flask_security import Security, SQLAlchemyUserDatastore
    from celery import Celery

    mail = Mail()
    security = Security()
    celery = Celery()


    @celery.task
    def send_flask_mail(**kwargs):
        # If you use Flask_Mail - it needs an app context
        with app.app_context():
            mail.send(Message(**kwargs))

    def create_app(config):
        """Initialize Flask instance."""

        app = Flask(__name__)
        app.config.from_object(config)

        mail.init_app(app)
        datastore = SQLAlchemyUserDatastore(db, User, Role)
        security.init_app(app, datastore, mail_util_cls=MyMailUtil)

        return app

.. _Celery: http://www.celeryproject.org/


.. _responsetopic:

Responses
---------
Flask-Security will likely be a very small piece of your application,
so Flask-Security makes it easy to override all aspects of API responses.

JSON Response
+++++++++++++
Applications that support a JSON based API need to be able to have a uniform
API response. Flask-Security has a default way to render its API responses - which can
be easily overridden by providing a callback function via :meth:`.Security.render_json`.
Be aware that Flask-Security registers
its own JsonEncoder on its blueprint.

401, 403, Oh My
+++++++++++++++
For a very long read and discussion; look at `this`_. Out of the box, Flask-Security in
tandem with Flask-Login, behave as follows:

    * If authentication fails as the result of a `@login_required`, `@auth_required("session", "token")`,
      or `@token_auth_required` then if the request 'wants' a JSON
      response, :meth:`.Security.render_json` is called with a 401 status code. If not
      then flask_login.LoginManager.unauthorized() is called. By default THAT will redirect to
      a login view.

    * If authentication fails as the result of a `@http_auth_required` or `@auth_required("basic")`
      then a 401 is returned along with the http header ``WWW-Authenticate`` set to
      ``Basic realm="xxxx"``. The realm name is defined by :py:data:`SECURITY_DEFAULT_HTTP_AUTH_REALM`.

    * If authorization fails as the result of `@roles_required`, `@roles_accepted`,
      `@permissions_required`, or `@permissions_accepted`, then if the request 'wants' a JSON
      response, :meth:`.Security.render_json` is called with a 403 status code. If not,
      then if :py:data:`SECURITY_UNAUTHORIZED_VIEW` is defined, the response will redirected.
      If :py:data:`SECURITY_UNAUTHORIZED_VIEW` is not defined, then ``abort(403)`` is called.

All this can be easily changed by registering any or all of :meth:`.Security.render_json`,
:meth:`.Security.unauthn_handler` and :meth:`.Security.unauthz_handler`.

The decision on whether to return JSON is based on:

    * Was the request content-type "application/json" (e.g. request.is_json()) OR

    * Is the 'best' value of the ``Accept`` HTTP header "application/json"


.. _`this`: https://stackoverflow.com/questions/3297048/403-forbidden-vs-401-unauthorized-http-responses

Authorization with OAuth2
-------------------------

Flask-Security can be set up to co-operate with `Flask-OAuthlib`_,
by implementing a custom request loader that authorizes a user based
either on a `Bearer` token in the HTTP `Authorization` header, or on the
Flask-Security standard authorization logic::

    from flask_oauthlib.provider import OAuth2Provider
    from flask_security import AnonymousUser
    from flask_security.core import (
        _user_loader as _flask_security_user_loader,
        _request_loader as _flask_security_request_loader)
    from flask_security.utils import config_value as security_config_value

    oauth = OAuth2Provider(app)

    def _request_loader(request):
        """
        Load user from OAuth2 Authentication header or using
        Flask-Security's request loader.
        """
        user = None

        if hasattr(request, 'oauth'):
            user = request.oauth.user
        else:
            # Need this try stmt in case oauthlib sometimes throws:
            # AttributeError: dict object has no attribute startswith
            try:
                is_valid, oauth_request = oauth.verify_request(scopes=[])
                if is_valid:
                    user = oauth_request.user
            except AttributeError:
                pass

        if not user:
            user = _flask_security_request_loader(request)

        return user

    def _get_login_manager(app, anonymous_user):
        """Prepare a login manager for Flask-Security to use."""
        login_manager = LoginManager()

        login_manager.anonymous_user = anonymous_user or AnonymousUser
        login_manager.login_view = '{0}.login'.format(
            security_config_value('BLUEPRINT_NAME', app=app))
        login_manager.user_loader(_flask_security_user_loader)
        login_manager.request_loader(_request_loader)

        if security_config_value('FLASH_MESSAGES', app=app):
            (login_manager.login_message,
             login_manager.login_message_category) = (
                security_config_value('MSG_LOGIN', app=app))
            (login_manager.needs_refresh_message,
             login_manager.needs_refresh_message_category) = (
                security_config_value('MSG_REFRESH', app=app))
        else:
            login_manager.login_message = None
            login_manager.needs_refresh_message = None

        login_manager.init_app(app)
        return login_manager

    security = Security(
        app, user_datastore,
        login_manager=_get_login_manager(app, anonymous_user=None))


.. _Flask-OAuthlib: https://flask-oauthlib.readthedocs.io/
