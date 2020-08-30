Two-factor Configurations
=========================

Two-factor authentication provides a second layer of security to any type of
login, requiring extra information or a secondary device to log in, in addition
to ones login credentials. The added feature includes the ability to add a
secondary authentication method using either via email, sms message, or an
Authenticator app such as Google, Lastpass, or Authy.

The following code sample illustrates how to get started as quickly as
possible using SQLAlchemy and two-factor feature:

Basic SQLAlchemy Two-Factor Application
+++++++++++++++++++++++++++++++++++++++

SQLAlchemy Install requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

     $ mkvirtualenv <your-app-name>
     $ pip install flask-security-too flask-sqlalchemy cryptography pyqrcode


Two-factor Application
~~~~~~~~~~~~~~~~~~~~~~

The following code sample illustrates how to get started as quickly as
possible using SQLAlchemy:

::

    from flask import Flask, current_app, render_template
    from flask_sqlalchemy import SQLAlchemy
    from flask_security import Security, SQLAlchemyUserDatastore, \
        UserMixin, RoleMixin, login_required


    # At top of file
    from flask_mail import Mail


    # Convenient references
    from werkzeug.datastructures import MultiDict
    from werkzeug.local import LocalProxy


    _security = LocalProxy(lambda: current_app.extensions['security'])

    _datastore = LocalProxy(lambda: _security.datastore)

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
    app.config['SECURITY_TWO_FACTOR_RESCUE_MAIL'] = 'put_your_mail@gmail.com'

    # Generate a good totp secret using: passlib.totp.generate_secret()
    app.config['SECURITY_TOTP_SECRETS'] = {"1": "TjQ9Qa31VOrfEzuPy4VHQWPCTmRzCnFzMKLxXYiZu9B"}
    app.config['SECURITY_TOTP_ISSUER'] = 'put_your_app_name'

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
        password = db.Column(db.String(255))
        active = db.Column(db.Boolean())
        confirmed_at = db.Column(db.DateTime())
        roles = db.relationship('Role', secondary=roles_users,
                                backref=db.backref('users', lazy='dynamic'))
        tf_phone_number = db.Column(db.String(64))
        tf_primary_method = db.Column(db.String(140))
        tf_totp_secret = db.Column(db.String(255))

    # Setup Flask-Security
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security = Security(app, user_datastore)

    mail = Mail(app)

    # Create a user to test with
    @app.before_first_request
    def create_user():
        db.create_all()
        user_datastore.create_user(email='gal@lp.com', password='password', username='gal',
                               tf_totp_secret=None, tf_primary_method=None)
        db.session.commit()

    # Views
    @app.route('/')
    @login_required
    def home():
        return render_template('index.html')

    if __name__ == '__main__':
        app.run()

.. _2fa_theory_of_operation:

Theory of Operation
+++++++++++++++++++++

.. note::
    The Two-factor feature requires that session cookies be received and sent as part of the API.
    This is true regardless of if the application uses forms or JSON.

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
method (and phone number is SMS). This will cause a code to be sent, and again use ``/tf-validate`` to confirm code. In order to setup an authenticator app
(such as lastpass, authy, google authenticator), you can do a GET on ``/tf-qrcode`` to generate the required information. Once the code  has been successfully
entered, the new configuration will be permanently stored.

Initial login/registration
~~~~~~~~~~~~~~~~~~~~~~~~~~~
This is basically a combination of the above two - initial POST to ``/login`` will return indicating that 2FA is required. The user must then POST to ``/tf_setup`` to setup
the desired 2FA method, and finally have the user enter the code and POST to ``/tf-validate``.

Rescue
~~~~~~
Life happens - if the user doesn't have their mobile devices (SMS) or authenticator app, then they can request using ``/tf-rescue`` endpoint to have the code sent to their email.
If they have lost access to their email, they can request an email be sent to the application administrators.
