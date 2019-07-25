Security Patterns
=================

.. _csrftopic:

CSRF
~~~~
By default, Flask-Security, via Flask-WTForms protects all form based POSTS
from CSRF attacks using well vetted per-session hidden-form-field csrf-tokens.

Any web application that relies on session cookies for authentication must have CSRF protection.
For more details please read this `OWASP cheatsheet <https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md>`_.
A couple important take-aways - first - it isn't about forms versus JSON - it is about
how the API is authenticated (session cookies versus authentication token). Second there is the
concern about 'login CSRF' - is protection needed prior to authentication (yes if
you have a really secure/popular site).

Flask-Security strives to support various options for both its endpoints (e.g. ``/login``)
and the application endpoints (protected with Flask-Security decorators such as ``@auth_required``).

If your application just uses forms that are derived from ``Flask-WTF::Flaskform`` - you are done.


CSRF: Single-Page-Applications and AJAX/XHR
++++++++++++++++++++++++++++++++++++++++++++
If you are thinking about using authentication tokens in your browser-based UI - read
`This article <https://stormpath.com/blog/where-to-store-your-jwts-cookies-vs-html5-web-storage>`_
on how and where to store authentication tokens. While the
article is talking about JWT it applies to flask_security tokens as well.

In general, it is considered more secure (and easier) to use sessions for browser
based UI, and tokens for service to service and scripts.

For SPA, and especially those that aren't served via your flask application, there are difficulties
with actually retrieving and using a CSRF token. There are 2 normal ways to do this:

 * Have the csrf-token available via a JSON GET request that can be attached as a
   header in every mutating request.
 * Have a cookie that can be read via javascript whose value is the csrf-token that
   can be attached as a header in every mutating request.

Flask-Security supports both solutions.

Explicit fetch and send of csrf-token
--------------------------------------
The current session CSRF token
is returned on every JSON GET request (to a Flask-Security endpoint) as ``response['csrf_token`]``.
For web applications that ARE served via flask, it is even easier to get the csrf-token -
`<https://flask-wtf.readthedocs.io/en/stable/csrf.html>`_ gives some useful tips.

Armed with the csrf-token, the UI must include that in every mutating operation.
Be careful NOT to include the csrf-token in non-mutating requests (such as GETs).
If your application uses GET to actually modify state - please stop.

An example using `axios <https://github.com/axios/axios>`_ ::


    # This will fetch the csrf-token. Note that we do a GET on the login endpoint
    # which will get us the csrf-token even though we aren't yet logged in.
    # Note further the 'data: null' and explicit Content-Type header - these are
    # critical, otherwise Flask-Security will return the login form.
    axios.get('/login',{data: null, headers: {'Content-Type': 'application/json'}}).then(function (resp) {
      csrf_token = resp.data['response']['csrf_token']
    })


    # This will add the token header to each outgoing mutating request.
    axios.interceptors.request.use(function (config) {
      if (["post", "delete", "patch", "put"].includes(config["method"])) {
        if (csrf_token !== '') {
          config.headers["X-CSRF-Token"] = csrf_token
        }
      }
      return config;
    }, function (error) {
      // Do something with request error
      return Promise.reject(error);
    });



Note that we use the header name ``X-CSRF-Token`` as that is one of the default
headers configured in Flask-WTF (``WTF_CSRF_HEADERS``)

To protect your application's endpoints (that presumably are not using Flask forms),
you need to enable CSRF as described in the FlaskWTF `documentation <https://flask-wtf.readthedocs.io/en/stable/csrf.html>`_: ::

    flask_wtf.CSRFProtect(app)

This will turn on CSRF protection on ALL endpoints, including Flask-Security. This protection differs slightly from
the default that is part of FlaskForm in that it will first look at the request body and see if it can find a form field that contains
the csrf-token, and if it can't, it will check if the request has a header that is listed in ``WTF_CSRF_HEADERS`` and use that.
Be aware that if you enable this it will ONLY work if you send the session cookie on each request.

Using a Cookie
--------------
You can instruct Flask-Security to send a cookie that contains the csrf token. This can be very
convenient since various javascript AJAX packages are pre-configured to extract the contents of a cookie
and send it on every mutating request as an HTTP header. `axios`_ for example has a default configuration
that it will look for a cookie named ``XSRF-TOKEN`` and will send the contents of that back
in an HTTP header called ``X-XSRF-Token``. This means that if you use that package you don't need to make
any changes to your UI and just need the following configuration::

    # Have cookie sent
    app.config["SECURITY_CSRF_COOKIE"] = {"key": "XSRF-TOKEN"}

    # Don't have csrf tokens expire (they are invalid after logout)
    app.config["WTF_CSRF_TIME_LIMIT"] = None

    # You can't get the cookie until you are logged in.
    app.config["SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS"] = True

    # Enable CSRF protection
    flask_wtf.CSRFProtect(app)

Angular's `httpClient`_ also supports this.


CSRF: Enable protection for session auth, but not token auth
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
As mentioned above, CSRF is critical for any mutating operation where the authentication credentials are 'invisibly' sent - such as a session cookie -
from a browser. But if your endpoint a) can only be authenticated with an attached token or b) can be called either via session OR token;
it is often desirable not to force token API users to deal with CSRF. To solve this, we need to keep CSRFProtect from checking the csrf-token early in the
request and instead defer that decision to later decorators/code. Flask-Security's authentication decorators (``auth_required``, ``auth_token_required``,
and ``http_auth_required`` all support calling csrf protection based on configuration::

    # Disable pre-request CSRF
    app.config[WTF_CSRF_CHECK_DEFAULT] = False

    # Check csrf for session and http auth (but not token)
    app.config[SECURITY_CSRF_PROTECT_MECHANISMS] = ["session", "basic"]

    # Enable CSRF protection
    flask_wtf.CSRFProtect(app)

    @app.route("/")
    @auth_required("token", "session")
    def home_page():

With this configuration, CSRF won't be required if the caller uses an authentication token, but if it uses
the session cookie it will.

CSRF: Pro-Tips
++++++++++++++
    #) Be aware that for CSRF to work, callers MUST send the session cookie. So
       for pure API, and no session cookie - there is no way to support 'login CSRF'.
       So your app must set ``SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS``
       (or clients must use CSRF/session cookie for logging
       in then once they have an authentication token, no further need for cookie).

    #) If you enable CSRFProtect(app) and you want to support non-form based JSON requests,
       then you must include the CSRF token in the header (e.g. X-CSRF-Token)

    #) You must enable CSRFProtect(app) if you want to accept the CSRF token in the request
       header.

    #) Annotate each of your endpoints with a @auth_required decorator (and don't rely
       on just a @role_required or @login_required decorator) so that Flask-Security
       get control at the appropriate place.

    #) If you can't use a decorator, Flask-Security exposes the underlying method
       ``handle_csrf``.

    #) Consider starting by setting ``SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS`` to True. Your
       application likely doesn't need 'login CSRF' protection, and it is frustrating
       to not even be able to login via API!

    #) If you have unauthenticated endpoints that you want to protect with CSRF then
       use the ``@unauth_csrf`` decorator.


.. _axios: https://github.com/axios/axios
.. _httpClient: https://angular.io/guide/http#security-xsrf-protection
