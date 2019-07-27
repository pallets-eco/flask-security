Working with Single Page Applications
======================================
`Single Page Applications (spa)`_ are a popular model for both separating
user interface from application/backend code as well as providing a responsive
user experience. Angular and Vue are popular Javescript frameworks for writing SPAs.
An added benefit is that the UI can be developed completely independently (in a separate repo)
and take advantage of the latest Javescript packing and bundling techonologies that are
evolving rapidly, and not make the Flask application have to deal with things
like Flask-Webpack or webassets.

For the purposes of this application note - this implies:

    * The user interface code is delivered by some other means than the Flask application.
      In particular this means that there are no opportunities to inject context/environment
      via a templating language.

    * The user interface interacts with the backend Flask application via JSON requests
      and responses - not forms.

    * SPAs are still browser based - so they have the same security vulnerabilities as
      traditional html/form-based applications.

    * SPAs handle all routing/redirection via code, so redirects need context.

Configuration
~~~~~~~~~~~~~
An example configuration::

    # no forms so no concept of flashing
    SECURITY_FLASH_MESSAGES = False

    # Need to be able to route backend flask API calls. Use 'accounts'
    # to be the Flask-Security endpoints.
    SECURITY_URL_PREFIX = '/api/accounts'

    # Turn on all the great Flask-Security features
    SECURITY_RECOVERABLE = True
    SECURITY_TRACKABLE = True
    SECURITY_CHANGEABLE = True
    SECURITY_CONFIRMABLE = True
    SECURITY_REGISTERABLE = True

    # These need to be defined to handle redirects
    # As defined in the API documentation - they will receive the relevant context
    SECURITY_POST_CONFIRM_VIEW = '/confirmed'
    SECURITY_CONFIRM_ERROR_VIEW = '/confirm-error
    SECURITY_RESET_VIEW = '/reset-password'
    SECURITY_RESET_ERROR_VIEW = '/reset-password'
    SECURITY_REDIRECT_BEHAVIOR = 'spa'

    # CSRF protection is critical for all session-based browser UIs

    # enforce CSRF protection for session / browser - but allow token-based
    # API calls to go through
    SECURITY_CSRF_PROTECT_MECHANISMS = ["session", "basic"]
    SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS = True

    # Send Cookie with csrf-token. This is the default for Axios and Angular.
    SECURITY_CSRF_COOKIE = {"key": "XSRF-TOKEN"}
    WTF_CSRF_CHECK_DEFAULT = False
    WTF_CSRF_TIME_LIMIT = None

    # In your app
    # Enable CSRF on all api endpoints.
    flask_wtf.CSRFProtect(app)

    # Initialize Flask-Security
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security = Security(app, user_datastore)

    # Optionally define and set unauthorized callbacks
    security.login_manager.unauthorized_handler(unauth)
    security.unauthorized_handler(unauth)

When in development mode, the Flask application will run by default on port 5000.
The UI might want to run on port 8080. In order to test redirects you need to set::

    SECURITY_REDIRECT_HOST = 'localhost:8080'

Security Considerations
~~~~~~~~~~~~~~~~~~~~~~~~
Static elements such as your UI should be served with an industrial-grade web server - such
as `Nginx`_. This is also where various security measures should be handled such as injecting
standard security headers such as:

    * ``Strict-Transport-Security``
    * ``X-Frame-Options``
    * ``Content Security Policy``


.. _Single Page Applications (spa): https://en.wikipedia.org/wiki/Single-page_application
.. _Nginx: https://www.nginx.com/
