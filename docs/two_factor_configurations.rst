Two-factor Configurations
=========================

Two-factor authentication provides a second layer of security to any type of
login, requiring extra information or a secondary device to log in, in addition
to ones login credentials. The added feature includes the ability to add a
secondary authentication method using either via email, sms message, or an
Authenticator app such as Google, Lastpass, or Authy.

The following code sample illustrates how to get started as quickly as
possible using SQLAlchemy and two-factor feature. In this example both
email and an authenticator app is supported as a second factor. See below
for information about SMS.

Basic SQLAlchemy Two-Factor Application
+++++++++++++++++++++++++++++++++++++++

SQLAlchemy Install requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

     $ python3 -m venv pymyenv
     $ . pymyenv/bin/activate
     $ pip install flask-security-too[common,mfa,fsqla]


Two-factor Application
~~~~~~~~~~~~~~~~~~~~~~

The following code sample illustrates how to get started as quickly as
possible using SQLAlchemy:

::

    import os
    from flask import Flask, current_app, render_template_string
    from flask_sqlalchemy import SQLAlchemy
    from flask_security import Security, SQLAlchemyUserDatastore, \
        UserMixin, RoleMixin, auth_required
    from flask_mailman import Mail

    # Create app
    app = Flask(__name__)
    app.config['DEBUG'] = True
    # Generate a nice key using secrets.token_urlsafe()
    app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", 'pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw')
    # Bcrypt is set as default SECURITY_PASSWORD_HASH, which requires a salt
    # Generate a good salt using: secrets.SystemRandom().getrandbits(128)
    app.config['SECURITY_PASSWORD_SALT'] = os.environ.get("SECURITY_PASSWORD_SALT", '146585145368132386173505678016728509634')

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'

    app.config['SECURITY_TWO_FACTOR_ENABLED_METHODS'] = ['email',
      'authenticator']  # 'sms' also valid but requires an sms provider
    app.config['SECURITY_TWO_FACTOR'] = True
    app.config['SECURITY_TWO_FACTOR_RESCUE_MAIL'] = "put_your_mail@gmail.com"

    app.config['SECURITY_TWO_FACTOR_ALWAYS_VALIDATE'] = False
    app.config['SECURITY_TWO_FACTOR_LOGIN_VALIDITY'] = "1 week"

    # Generate a good totp secret using: passlib.totp.generate_secret()
    app.config['SECURITY_TOTP_SECRETS'] = {"1": "TjQ9Qa31VOrfEzuPy4VHQWPCTmRzCnFzMKLxXYiZu9B"}
    app.config['SECURITY_TOTP_ISSUER'] = "put_your_app_name"

    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
    }
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Create database connection object
    db = SQLAlchemy(app)

    # Define models
    roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

    class Role(db.Model, RoleMixin):
      id = db.Column(db.Integer(), primary_key=True)
      name = db.Column(db.String(80), unique=True)
      description = db.Column(db.String(255))

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(255), unique=True)
        # Make username unique but not required.
        username = db.Column(db.String(255), unique=True, nullable=True)
        password = db.Column(db.String(255))
        active = db.Column(db.Boolean())
        fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
        confirmed_at = db.Column(db.DateTime())
        roles = db.relationship('Role', secondary=roles_users,
                                backref=db.backref('users', lazy='dynamic'))
        tf_phone_number = db.Column(db.String(128), nullable=True)
        tf_primary_method = db.Column(db.String(64), nullable=True)
        tf_totp_secret = db.Column(db.String(255), nullable=True)

    # Setup Flask-Security
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(app, user_datastore)

    mail = Mail(app)

    # Views
    @app.route('/')
    @auth_required()
    def home():
        return render_template_string("Hello {{ current_user.email }}")

    # one time setup
    with app.app_context():
        # Create a user to test with
        db.create_all()
        if not app.security.datastore.find_user(email='test@me.com'):
            app.security.datastore.create_user(email='test@me.com', password='password')
        db.session.commit()

    if __name__ == '__main__':
        app.run()

Adding SMS
++++++++++

Using SMS as a second factor requires access to an SMS service provider such as "Twilio".
Flask-Security supports Twilio out of the box.
For other sms service providers you will need to subclass :class:`.SmsSenderBaseClass` and register it:

    .. code-block:: python

        SmsSenderFactory.senders[<service-name>] = <service-class>

You need to install additional packages::

    pip install phonenumberslite twilio

And set additional configuration variables::

    app.config["SECURITY_TWO_FACTOR_ENABLED_METHODS"] = ['email',
      'authenticator', 'sms']
    app.config["SECURITY_SMS_SERVICE"] = "Twilio"
    app.config["SECURITY_SMS_SERVICE_CONFIG" =
      {'ACCOUNT_SID': <from twilio>, 'AUTH_TOKEN': <from twilio>, 'PHONE_NUMBER': <from twilio>}

.. _2fa_theory_of_operation:

Theory of Operation
+++++++++++++++++++++

.. note::
    The Two-factor feature requires that session cookies be received and sent as part of the API.
    This is true regardless of whether the application uses forms or JSON.

The Two-factor (2FA) API has four paths:

    - Normal login once everything set up
    - Changing 2FA setup
    - Initial login/registration when 2FA is required
    - Rescue

When using forms, the flow from one state to the next is handled by the forms themselves. When using JSON
the application must of course explicitly access the appropriate endpoints. The descriptions below describe the JSON access pattern.

Normal Login
~~~~~~~~~~~~
In the normal case, when the user has already setup their preferred 2FA method (e.g. email, SMS, authenticator app),
then the flow starts with the authentication process using the ``/login`` or ``/us-signin`` endpoints, providing
their identity and password. If 2FA is required, the response will indicate that. Then, the application must POST to the ``/tf-validate``
with the correct code.

Changing 2FA Setup
~~~~~~~~~~~~~~~~~~~
An authenticated user can change their 2FA configuration (primary_method, phone number, etc.). In order to prevent a user from being
locked out, the new configuration must be validated before it is stored permanently. The user starts with a GET on ``/tf-setup``. This will return
a list of configured 2FA methods the user can choose from, and the existing configuration. This must be followed with a POST on ``/tf-setup`` with the new primary
method (and phone number if SMS). In the case of SMS, a code will be sent to the phone/device and again use ``/tf-validate`` to confirm code.
In the case of setting up an authenticator app, the response to the POST will contain the QRcode image as well
as the required information for manual entry.
Once the code  has been successfully
entered, the new configuration will be permanently stored.

Initial login/registration
~~~~~~~~~~~~~~~~~~~~~~~~~~~
This is basically a combination of the above two - initial POST to ``/login`` will return indicating that 2FA is required. The user must then POST to ``/tf-setup`` to setup
the desired 2FA method, and finally have the user enter the code and POST to ``/tf-validate``.

Rescue
~~~~~~
Life happens - if the user doesn't have their mobile devices (SMS) or authenticator app, then they can use the ``/tf-rescue`` endpoint to
see possible recovery options. Flask-Security supports the following:

    - Have a one-time code sent to their email (if :py:data:`SECURITY_TWO_FACTOR_RESCUE_EMAIL` is set to ``True``).
    - Send an email to the application administrators.
    - Use a previously setup one-time recovery code (see :py:data:`SECURITY_MULTI_FACTOR_RECOVERY_CODES`)

Validity
++++++++
Sometimes it can be preferable to enter the 2FA code once a day/week/month, especially if a user logs in and out of a website multiple times.  This allows the
security of a two factor authentication but with a slightly better user experience.  This can be achieved by setting :py:data:`SECURITY_TWO_FACTOR_ALWAYS_VALIDATE` to ``False``,
and clicking the 'Remember' button on the login form. Once the two factor code is validated, a cookie is set to allow skipping the validation step.  The cookie is named
``tf_validity`` and contains the signed token containing the user's ``fs_uniquifier``.  The cookie and token are both set to expire after the time delta given in
:py:data:`SECURITY_TWO_FACTOR_LOGIN_VALIDITY`.  Note that setting ``SECURITY_TWO_FACTOR_LOGIN_VALIDITY`` to 0 is equivalent to ``SECURITY_TWO_FACTOR_ALWAYS_VALIDATE`` being ``True``.
