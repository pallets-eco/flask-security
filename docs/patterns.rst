Security Patterns
=================

.. danger::
    Be aware that starting in Flask 2.2.0, they recommend extensions store context information
    on ``g`` which is the application context. Prior to this many extensions (including
    Flask-Security and Flask-Login) stored things like user credential information on the
    request context. These are now stored on ``g`` i.e. the application context. It is imperative
    that applications not mistakenly push their own application context and forget to pop it - in that
    case Flask won't push a new application context nor will it pop it at the end of the request - thus
    credential information could leak from one user request to another.

Authentication and Authorization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Flask-Security provides a set of authentication decorators:

 * :func:`.auth_required`

 * :func:`.http_auth_required`

 * :func:`.auth_token_required`

and a set of authorization decorators:

 * :func:`.roles_required`

 * :func:`.roles_accepted`

 * :func:`.permissions_required`

 * :func:`.permissions_accepted`

In addition, Flask-Login provides @login_required. In order to take advantage of all the
Flask-Security features, it is recommended to NOT use @login_required.

Also, if you annotate your endpoints with JUST an authorization decorator, you will never
get a 401 response, and (for forms) you won't be redirected to your login page. In this case
you will always get a 403 status code (assuming you don't override the default handlers).

While these annotations are quick and easy, it is likely that they won't completely satisfy
all an application's authorization requirements. A common example might be that a user can
only edit their own posts/documents. In cases like this - it is nice to have a uniform way
of handling all authorization errors. A simple way to do this is to use a special exception
class that you can raise either in response to Flask-Security authorization failures, or in your
own code. Then use Flask's ``errorhandler`` to catch that exception and create the appropriate API response::

    Class MyForbiddenException(Exception):
        def __init__(self, msg='Not permitted with your privileges', status=http.HTTPStatus.FORBIDDEN):
            self.info = {'status': status, 'msgs': [msg]}

    _security = app.extensions["security"]

    @_security.unauthz_handler
    def my_unauthz_handler(func, params):
        raise MyForbiddenException()

    @app.errorhandler(MyForbiddenException)
    def my_exception(ex):
        return flask.jsonify(ex.info), ex.info['status']

    @app.route('/doc/<int:doc_id>', methods=['PATCH'])
    @auth_required('token', 'session')
    def doc_patch(doc_id):
        doc = fetch_doc(doc_id)
        if not current_user.has_role('admin') and doc.owner != current_user:
            raise MyForbiddenException(msg='You can only update docs you own')


A note about Basic Auth
+++++++++++++++++++++++
Basic Auth is supported in Flask-Security, using the @http_auth_required() decorator. If a request for an endpoint
protected with @http_auth_required is received, and the request doesn't contain the appropriate HTTP Headers, a 401 is returned
along with the required WWW-Authenticate header. In this case there won't be a usable session cookie returned so all future requests
will also require credentials to be sent. Effectively the caller is temporarily 'logged in' at the beginning of each request and 'logged out' again
at the end of the request. Most (all?) browsers intercept this response and pop up a login dialog box and remember, for the site, the entered credentials.
This effectively bypasses any of the normal Flask-Security login forms. By default, the Flask-Security endpoints that require the caller be
authenticated do NOT support ``basic`` - however the :py:data:`SECURITY_API_ENABLED_METHODS` can be used to override this.

Freshness
++++++++++
A common pattern for browser-based sites is to use sessions to manage identity. This is usually
implemented using session cookies. These cookies expire once the session (browser tab) is closed. This is very
convenient, and keeps the users from having to constantly re-authenticate. The downside is that sessions can easily be
open for days or weeks. This adds to the security risk that some bad-actor or XSS gets control of the browser and then can
do anything the user can. To mitigate that, operations that change fundamental identity characteristics (such as email, password, etc.)
can be protected by requiring a 'fresh' or recent authentication. Flask-Security supports this with the following:

    - :func:`.auth_required` takes parameters that define how recent the authentication must have happened. In addition a grace
      period can be specified so that multiple step operations don't require re-authentication in the middle.
    - A default :meth:`.Security.reauthn_handler` that is called when a request fails the recent authentication check.
    - :py:data:`SECURITY_VERIFY_URL` and :py:data:`SECURITY_US_VERIFY_URL` endpoints that request the user to re-authenticate.
    - ``VerifyForm`` and ``UsVerifyForm`` forms that can be extended.

Flask-Security itself uses this as part of securing the :ref:`unified-sign-in`, :ref:`two-factor`, and :ref:`webauthn` setup endpoints.

.. _pass_validation_topic:

Password Validation and Complexity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
There is a large body of references (and endless discussions) around how to get users to create
good passwords. The `OWASP Authenication cheatsheet <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>`_
is a useful place to start. Flask-Security has a default password validator that:

 * Checks for minimum and maximum length (minimum is configurable via :py:data:`SECURITY_PASSWORD_LENGTH_MIN`).
   The default is 8 characters as defined by `NIST <https://pages.nist.gov/800-63-3/sp800-63b.html>`_.
 * If :py:data:`SECURITY_PASSWORD_CHECK_BREACHED` is set, will use the API for `haveibeenpwned <https://haveibeenpwned.com>`_ to
   check if the password is on a list of breached passwords. The configuration variable :py:data:`SECURITY_PASSWORD_BREACHED_COUNT`
   can be used to set the minimum allowable 'breaches'.
 * If :py:data:`SECURITY_PASSWORD_COMPLEXITY_CHECKER` is set to ``zxcvbn`` and the
   package `zxcvbn <https://pypi.org/project/zxcvbn/>`_ is installed, it will check the password for complexity.

Be aware that ``zxcvbn`` is not actively being maintained, and has localization issues.

In addition to validation, unicode passwords should be normalized as specified
by NIST requirement: `5.1.1.2 Memorized Secret Verifiers`_. Normalization can
be disabled by setting the :py:data:`SECURITY_PASSWORD_NORMALIZE_FORM` to ``None``.
Validation and normalization is encapsulated in :class:`.PasswordUtil`.
This can be overridden by passing your class at app initialization time.
The :meth:`.PasswordUtil.validate` is passed additional kwargs to allow custom
validators more flexibility.
A custom validator can still call the underlying methods where appropriate:
:func:`flask_security.password_length_validator`, :func:`flask_security.password_complexity_validator`,
and :func:`flask_security.password_breached_validator`.

.. _5.1.1.2 Memorized Secret Verifiers: https://pages.nist.gov/800-63-3/sp800-63b.html#sec5


.. _generic_responses:

Generic Responses - Avoiding User Enumeration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
How an application responds to API requests that contain identity or authentication information
can give would-be attackers insight into active users on the system. OWASP has a great `cheat-sheet`_ describing
this and useful ways to avoid it. Flask-Security supports this by setting the
:py:data:`SECURITY_RETURN_GENERIC_RESPONSES` configuration to ``True``. As documented in the cheat-sheet - this does
come with some usability concerns. The following endpoints are affected:

    * :py:data:`SECURITY_REGISTER_URL` - The same response will be returned whether the email (or username) is already in the
      system or not. JSON requests will ALWAYS return 200. If :py:data:`SECURITY_CONFIRMABLE` is set (it should be!), the
      `SECURITY_MSG_CONFIRM_REGISTRATION` message will be flashed for both new and existing email addresses. Detailed errors will still
      be returned for things like insufficient password complexity, etc.. In the case of trying to register an existing email, an email will be sent to that email address
      explaining that they are already registered and displaying the associated username (if any) and provide a hint on how to reset their
      password if they forgot it. In the case of a new email but an already registered username, an email will be sent saying that the
      user must try registering again with a different username.
    * :py:data:`SECURITY_LOGIN_URL` - For any errors (unknown username, inactive account, bad password) the `SECURITY_MSG_GENERIC_AUTHN_FAILED`
      message will be returned.
    * :py:data:`SECURITY_RESET_URL` - In all cases the `SECURITY_MSG_PASSWORD_RESET_REQUEST` message will be flashed. For JSON
      a 200 will always be returned (whether an email was sent or not).
      ``Note``: If the application overrides the form and adds an additional field (e.g. `captcha`) and that field has
      a validation error, a normal form error response will be returned (and JSON will return a 400).
    * :py:data:`SECURITY_CONFIRM_URL` - In all cases the `SECURITY_MSG_CONFIRMATION_REQUEST` message will be flashed. For JSON
      a 200 will always be returned (whether an email was sent or not).
      ``Note``: If the application overrides the form and adds an additional field (e.g. `captcha`) and that field has
      a validation error, a normal form error response will be returned (and JSON will return a 400).
    * :py:data:`SECURITY_US_SIGNIN_SEND_CODE_URL` - The `SECURITY_MSG_GENERIC_US_SIGNIN` message will be flashed in all cases -
      whether a selected method is setup for the user or not.
    * :py:data:`SECURITY_US_SIGNIN_URL` - For any errors (unknown username, inactive account, bad passcode) the `SECURITY_MSG_GENERIC_AUTHN_FAILED`
      message will be returned.
    * :py:data:`SECURITY_US_VERIFY_LINK_URL` - For any errors (unknown username, inactive account, bad passcode) the `SECURITY_MSG_GENERIC_AUTHN_FAILED`
      message will be returned.


In the case of an application using a ``username`` as an identity it should be noted that it is possible for a bad-actor to enumerate usernames, albeit slowly,
by parsing emails.

Note also that :py:data:`SECURITY_REQUIRES_CONFIRMATION_ERROR_VIEW` is ignored in these cases. If your application is using WebAuthn, be sure
to set :py:data:`SECURITY_WAN_ALLOW_USER_HINTS` to ``False``.


.. _cheat-sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-and-error-messages

.. _csrftopic:

CSRF
~~~~
By default, Flask-Security, via Flask-WTForms protects all form based POSTS
from CSRF attacks using well vetted per-session hidden-form-field csrf-tokens.

Any web application that relies on session cookies for authentication must have CSRF protection.
For more details please read this `OWASP CSRF cheatsheet <https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md>`_.
A couple important take-aways - first - it isn't about forms versus JSON - it is about
how the API is authenticated (session cookies versus authentication token). Second there is the
concern about 'login CSRF' - is protection needed prior to authentication (yes if
you have a really secure/popular site).

Flask-Security strives to support various options for both its endpoints (e.g. ``/login``)
and the application endpoints (protected with Flask-Security decorators such as :func:`.auth_required`).

If your application just uses forms that are derived from ``Flask-WTF::Flaskform`` - you are done.


CSRF: Single-Page-Applications and AJAX/XHR
++++++++++++++++++++++++++++++++++++++++++++
If you are thinking about using authentication tokens in your browser-based UI - read
`this article <https://stormpath.com/blog/where-to-store-your-jwts-cookies-vs-html5-web-storage>`_
on how and where to store authentication tokens. While the
article is talking about JWT it applies to Flask-Security tokens as well.

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
`<https://flask-wtf.readthedocs.io/en/1.0.x/csrf/>`_ gives some useful tips.

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
headers configured in Flask-WTF (*WTF_CSRF_HEADERS*)

To protect your application's endpoints (that presumably are not using Flask forms),
you need to enable CSRF as described in the FlaskWTF `documentation <https://flask-wtf.readthedocs.io/en/1.1.x/csrf/>`_: ::

    flask_wtf.CSRFProtect(app)

This will turn on CSRF protection on ALL endpoints, including Flask-Security. This protection differs slightly from
the default that is part of FlaskForm in that it will first look at the request body and see if it can find a form field that contains
the csrf-token, and if it can't, it will check if the request has a header that is listed in *WTF_CSRF_HEADERS* and use that.
Be aware that if you enable this it will ONLY work if you send the session cookie on each request.

.. note::
    It is IMPORTANT that you initialize/call ``CSRFProtect`` PRIOR to initializing Flask_Security.


Using a Cookie
--------------
You can instruct Flask-Security to send a cookie that contains the csrf token. This can be very
convenient since various javascript AJAX packages are pre-configured to extract the contents of a cookie
and send it on every mutating request as an HTTP header. `axios`_ for example has a default configuration
that it will look for a cookie named ``XSRF-TOKEN`` and will send the contents of that back
in an HTTP header called ``X-XSRF-Token``. This means that if you use that package you don't need to make
any changes to your UI and just need the following configuration::

    # Have cookie sent
    app.config["SECURITY_CSRF_COOKIE_NAME"] = "XSRF-TOKEN"

    # Don't have csrf tokens expire (they are invalid after logout)
    app.config["WTF_CSRF_TIME_LIMIT"] = None

    # You can't get the cookie until you are logged in.
    app.config["SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS"] = True

    # Enable CSRF protection
    flask_wtf.CSRFProtect(app)

Angular's `httpClient`_ also supports this.

For React based projects you are free to choose your http client (`fetch` is bundled by default). Retrieving the token is easy::

    fetch(url, {
      credentials: 'include',
      mode: 'cors',
      headers: {
        'Accept': 'application/json',
        'X-XSRF-TOKEN': getCookieValue('XSRF-TOKEN')
      }
    });

Sending the token on every mutating request is something that you should implement yourself. As an example an API call to an API
endpoint that does CSRF validation::

    function addUser(details) {
      return fetch('https://api.example.com/user', {
        mode: 'cors',
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify(details),
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-XSRF-TOKEN': getCookieValue('XSRF-TOKEN')
        }
      }).then(response => {
        return response.json().then(data => {
          if (response.ok) {
            return data;
          } else {
            return Promise.reject({status: response.status, data});
          }
        });
      });
    }

When you have axios setup correctly, this is a lot easier::

    function addUser(details) {
      return axios.post('https://api.example.com/user', details);
    }


CSRF: Enable protection for session auth, but not token auth
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
As mentioned above, CSRF is critical for any mutating operation where the authentication credentials are 'invisibly' sent - such as a session cookie -
from a browser. But if your endpoint a) can only be authenticated with an attached token or b) can be called either via session OR token;
it is often desirable not to force token API users to deal with CSRF. To solve this, we need to keep CSRFProtect from checking the csrf-token early in the
request and instead defer that decision to later decorators/code. Flask-Security's authentication decorators (:func:`.auth_required`,
:func:`.auth_token_required`, and :func:`.http_auth_required` all support calling csrf protection based on configuration::

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
       for pure API (token based), and no session cookie - there is no way to support 'login CSRF'.
       So your app must set :py:data:`SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS`
       (or clients must use CSRF/session cookie for logging
       in then once they have an authentication token, no further need for cookie).

    #) If you enable CSRFProtect(app) and you want to support non-form based JSON requests,
       then you must include the CSRF token in the header (e.g. X-CSRF-Token)

    #) You must enable CSRFProtect(app) if you want to accept the CSRF token in the request
       header.

    #) Annotate each of your endpoints with a @auth_required decorator (and don't rely
       on just a @role_required or @login_required decorator) so that Flask-Security
       gets control at the appropriate place.

    #) If you can't use a decorator, Flask-Security exposes the underlying method
       :func:`flask_security.handle_csrf`.

    #) Consider starting by setting :py:data:`SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS` to True. Your
       application likely doesn't need 'login CSRF' protection, and it is frustrating
       to not even be able to login via API!

    #) If you have unauthenticated endpoints that you want to protect with CSRF then
       use the :func:`flask_security.unauth_csrf` decorator.


.. _axios: https://github.com/axios/axios
.. _httpClient: https://angular.io/guide/http#security-xsrf-protection
