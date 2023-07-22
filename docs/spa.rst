Working with Single Page Applications
======================================
`Single Page Applications (spa)`_ are a popular model for both separating
user interface from application/backend code as well as providing a responsive
user experience. Angular and Vue are popular Javascript frameworks for writing SPAs.
An added benefit is that the UI can be developed completely independently (in a separate repo)
and take advantage of the latest Javascript packing and bundling technologies that are
evolving rapidly, and not make the Flask application have to deal with things
like Flask-Webpack or webassets.

For the purposes of this application note - this implies:

    * The user interface code is delivered by some other means than the Flask application.
      In particular this means that there are no opportunities to inject context/environment
      via a templating language.

    * The user interface interacts with the backend Flask application via JSON requests
      and responses - not forms. The external (json/form) API is described `here`_

.. _here: _static/openapi_view.html

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
    SECURITY_UNIFIED_SIGNIN = True

    # These need to be defined to handle redirects
    # As defined in the API documentation - they will receive the relevant context
    SECURITY_POST_CONFIRM_VIEW = "/confirmed"
    SECURITY_CONFIRM_ERROR_VIEW = "/confirm-error"
    SECURITY_RESET_VIEW = "/reset-password"
    SECURITY_RESET_ERROR_VIEW = "/reset-password-error"
    SECURITY_REDIRECT_BEHAVIOR = "spa"

    # CSRF protection is critical for all session-based browser UIs

    # enforce CSRF protection for session / browser - but allow token-based
    # API calls to go through
    SECURITY_CSRF_PROTECT_MECHANISMS = ["session", "basic"]
    SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS = True

    # Send Cookie with csrf-token. This is the default for Axios and Angular.
    SECURITY_CSRF_COOKIE_NAME = "XSRF-TOKEN"
    WTF_CSRF_CHECK_DEFAULT = False
    WTF_CSRF_TIME_LIMIT = None

    # In your app
    # Enable CSRF on all api endpoints.
    flask_wtf.CSRFProtect(app)

    # Initialize Flask-Security
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security = Security(app, user_datastore)

    # Optionally define and set unauthorized callbacks
    security.unauthz_handler(<your unauth handler>)

When in development mode, the Flask application will run by default on port 5000.
The UI might want to run on port 8080. In order to test redirects you need to set::

    SECURITY_REDIRECT_HOST = 'localhost:8080'

Client side authentication options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Depending on your SPA architecture and vision you can choose between cookie or token based authentication.

For both there is more documentation and some examples. In both cases, you need to understand and handle :ref:`csrftopic` concerns.

Security Considerations
~~~~~~~~~~~~~~~~~~~~~~~~
Static elements such as your UI should be served with an industrial-grade web server - such
as `Nginx`_. This is also where various security measures should be handled such as injecting
standard security headers such as:

    * ``Strict-Transport-Security``
    * ``X-Frame-Options``
    * ``Content Security Policy``
    * ``X-Content-Type-Options``
    * ``X-XSS-Protection``
    * ``Referrer policy``

There are a lot of different ways to host a SPA as the javascript part itself is quit easily hosted from any static
webserver. A couple of deployment options and their configurations will be describer here.

Nginx
~~~~~
When serving a SPA from a Nginx webserver the Flask backend, with Flask-Security-Too, will probably be served via
Nginx's reverse proxy feature. The javascript is served from Nginx itself and all calls to a certain path will be routed
to the reversed proxy. The example below routes all http requests to *"/api/"* to the Flask backend and handles all other
requests directly from javascript. This has a couple of benefits as all the requests happen within the same domain so you
don't have to worry about `CORS`_ problems::

    server {
        listen       80;
        server_name  www.example.com;

        #access_log  /var/log/nginx/host.access.log  main;

        root   /usr/share/nginx/html;
        index index.html;

        location / {
            try_files $uri $uri/ /index.html;
        }

        # Location of assets folder
        location ~ ^/(static)/  {
            gzip_static on;
            gzip_types text/plain text/xml text/css text/comma-separated-values
                text/javascript application/x-javascript application/atom+xml;
            expires max;
        }

        # redirect server error pages to the static page /50x.html
        # 400 error's will be handled from the SPA
        error_page   500 502 503 504  /50x.html;
            location = /50x.html {
        }

        # route all api requests to the flask app, served by gunicorn
        location /api/ {
            proxy_pass http://localhost:8080/api/;
        }

        # OR served via uwsgi
        location /api/ {
            include ..../uwsgi_params;
            uwsgi_pass unix:/tmp/uwsgi.sock;
            uwsgi_pass_header AUTHENTICATION-TOKEN;
        }
    }

.. note:: The example doesn't include SSL setup to keep it simple and still suitable for a more complex kubernetes setup
    where Nginx is often used as a load balancer and another Nginx with SSL setup runs in front of it.

Amazon lambda gateway / Serverless
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Most Flask apps can be deployed to Amazon's lambda gateway without much hassle by using `Zappa`_.
You'll get automatic horizontal scaling, seamless upgrades, automatic SSL certificate renewal and a very cheap way of
hosting a backend without being responsible for any infrastructure. Depending on how you design your app you could
choose to host your backend from an api specific domain: e.g. *api.example.com*. When your SPA deployment structure is
capable of routing the AJAX/XHR request from your javascript app to the separate backend; use it. When you want to use
the backend from another e.g. *www.example.com* you have some deal with some `CORS`_ setup as your browser will block
cross-domain POST requests. There is a Flask package for that: `Flask-CORS`_.

The setup of CORS is simple::

    CORS(
        app,
        supports_credentials=True,  # needed for cross domain cookie support
        resources="/*",
        allow_headers="*",
        origins="https://www.example.com",
        expose_headers="Authorization,Content-Type,Authentication-Token,XSRF-TOKEN",
    )

You can then host your javascript app from an S3 bucket, with or without Cloudfront, GH-pages or from any static webserver.

Some background material:

    * Specific to `S3`_ but easily adaptable.

    * `Flask-Talisman`_ - useful if serving everything from your Flask application - also
      useful as a good list of things to consider.

.. _Single Page Applications (spa): https://en.wikipedia.org/wiki/Single-page_application
.. _Nginx: https://www.nginx.com/
.. _S3: https://www.savjee.be/2018/05/Content-security-policy-and-aws-s3-cloudfront/
.. _Flask-Talisman: https://github.com/GoogleCloudPlatform/flask-talisman
.. _CORS: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
.. _Flask-CORS: https://github.com/corydolphin/flask-cors
.. _Zappa: https://github.com/Miserlou/Zappa
