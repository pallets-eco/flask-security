"""
test_oauthglue.py
~~~~~~~~~~~~~~~~~

OAuth glue tests - oauthglue is a very thin shim between FS and authlib

:copyright: (c) 2022-2026 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.
"""

import json
import pytest
import urllib.parse
from urllib.parse import parse_qsl, urlsplit

from flask import redirect
from flask_wtf import CSRFProtect

from flask_security import FsOAuthProvider
from tests.test_utils import (
    authenticate,
    capture_flashes,
    check_location,
    get_csrf_token,
    get_form_action,
    get_form_input_value,
    get_session,
    init_app_with_options,
    is_authenticated,
    json_authenticate,
    logout,
    reset_fresh,
    setup_tf_sms,
)

pytestmark = pytest.mark.oauth()


class MockRequestsResponse:
    # authlib returns a Requests Response
    def __init__(self, contents):
        self.contents = contents

    def json(self):
        return self.contents


class MockProvider:
    def __init__(self, name):
        self.name = name
        self.raise_exception = None
        self.identity = "matt@lp.com"

    def set_exception(self, raise_exception):
        self.raise_exception = raise_exception

    def set_identity(self, email):
        self.identity = email

    def get(self, field, token):
        resp = MockRequestsResponse({"email": self.identity})
        return resp

    def authorize_access_token(self):
        if self.raise_exception:
            raise self.raise_exception
        return "token"

    def authorize_redirect(self, uri):
        redirect_url = f"/whatever?redirect_uri={uri}"
        return redirect(urllib.parse.quote(redirect_url))


class MockAuthlibFlaskClient:
    def __init__(self):
        pass

    def register(self, name, **kwargs):
        setattr(self, name, MockProvider(name))


@pytest.mark.settings(oauth_enable=True, post_login_view="/post_login")
@pytest.mark.app_settings(wtf_csrf_enabled=True)
def test_github(app, sqlalchemy_datastore, get_message):
    CSRFProtect(app)
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    response = client.get("/login")
    github_url = get_form_action(response, 1)
    csrf_token = get_form_input_value(response, field_id="github_csrf_token")

    # make sure required CSRF
    response = client.post(github_url, follow_redirects=False)
    assert b"The CSRF token is missing" in response.data

    response = client.post(
        github_url, data=dict(csrf_token=csrf_token), follow_redirects=False
    )
    assert "/whatever" in response.location

    response = client.get("/login/oauthresponse/github", follow_redirects=False)
    assert response.status_code in [302, 303]
    assert "/post_login" in response.location
    # verify logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200


@pytest.mark.settings(
    oauth_enable=True, post_login_view="/post_login", csrf_ignore_unauth_endpoints=True
)
@pytest.mark.app_settings(wtf_csrf_enabled=True, wtf_csrf_check_default=False)
def test_github_nocsrf(app, sqlalchemy_datastore, get_message):
    # Test if ignore_unauth_endpoints is true - doesn't require CSRF
    CSRFProtect(app)
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    response = client.get("/login")
    github_url = get_form_action(response, 1)
    response = client.post(github_url, follow_redirects=False)
    assert "/whatever" in response.location


@pytest.mark.settings(oauth_enable=True, post_login_view="/post_login")
def test_outside_register(app, sqlalchemy_datastore, get_message):
    def myoauth_fetch_identity(oauth, token):
        resp = oauth.myoauth.get("user", token=token)
        profile = resp.json()
        return "email", profile["email"]

    authlib_oauth = MockAuthlibFlaskClient()
    authlib_oauth.register("myoauth")
    init_app_with_options(
        app, sqlalchemy_datastore, **{"security_args": {"oauth": authlib_oauth}}
    )
    # Have to register with Oauthglue.
    app.security.oauthglue.register_provider("myoauth", None, myoauth_fetch_identity)

    client = app.test_client()
    response = client.get("/login")
    myoauth_url = get_form_action(response, 2)

    response = client.post(myoauth_url, follow_redirects=False)
    assert "/whatever" in response.location

    response = client.get("/login/oauthresponse/myoauth", follow_redirects=False)
    assert response.status_code in [302, 303]
    assert "/post_login" in response.location
    # verify logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200


@pytest.mark.settings(oauth_enable=True)
def test_bad_api(app, sqlalchemy_datastore, get_message):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()

    response = client.post("/login/oauthstart/foobar")
    assert response.status_code == 404

    response = client.get("/login/oauthresponse/foobar")
    assert response.status_code == 404

    from authlib.integrations.base_client.errors import MismatchingStateError

    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.github.set_exception(MismatchingStateError)
    response = client.get("/login/oauthresponse/github", follow_redirects=True)
    assert response.status_code == 200
    assert (
        get_message(
            "OAUTH_HANDSHAKE_ERROR",
            exerror="mismatching_state",
            exdesc="CSRF Warning! State not equal in request and response.",
        )
        in response.data
    )


@pytest.mark.settings(oauth_enable=True)
def test_unknown_user(app, sqlalchemy_datastore, get_message):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.github.set_identity("jwag@lp.com")
    response = client.get("/login/oauthresponse/github", follow_redirects=True)
    assert get_message("IDENTITY_NOT_REGISTERED", id="jwag@lp.com") in response.data


@pytest.mark.settings(oauth_enable=True)
def test_disabled_user(app, sqlalchemy_datastore, get_message):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.github.set_identity("tiya@lp.com")  # disabled account
    response = client.get("/login/oauthresponse/github", follow_redirects=True)
    assert check_location(app, response.request.path, "/login")
    assert get_message("DISABLED_ACCOUNT") in response.data  # should be in flash


@pytest.mark.settings(oauth_enable=True)
def test_unicode_email(app, sqlalchemy_datastore, get_message):
    # Test that we normalize email response from oauth provider
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.github.set_identity(
        "matt@\N{FULLWIDTH LATIN SMALL LETTER L}\N{FULLWIDTH LATIN SMALL LETTER P}.com"
    )
    client.get("/login/oauthresponse/github", follow_redirects=True)
    assert is_authenticated(client, get_message)


@pytest.mark.settings(
    oauth_enable=True,
    USER_IDENTITY_ATTRIBUTES=[
        {"username": {"mapper": lambda x: x}},
    ],
)
def test_email_not_identity(app, sqlalchemy_datastore, get_message):
    # Test that if email isn't an identity attribute - can't use oauth to log in
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    response = client.get("/login/oauthresponse/github", follow_redirects=True)
    assert (
        b": (Config error - Invalid identity attribute: email). Please try again."
        in response.data
    )


def _locked(self, form_error):
    if self.email == "gal@lp.com":
        form_error.append("You are not allowed to do that")
        return True
    return False


@pytest.mark.app_settings(TESTING_USER_INJECT=dict(is_locked=_locked))
@pytest.mark.settings(oauth_enable=True)
def test_override_user_locked(app, sqlalchemy_datastore, get_message):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.github.set_identity("gal@lp.com")  # disabled account
    response = client.get("/login/oauthresponse/github", follow_redirects=True)
    assert check_location(app, response.request.path, "/login")
    assert b"You are not allowed to do that" in response.data  # should be in flash


@pytest.mark.two_factor()
@pytest.mark.settings(oauth_enable=True)
def test_tf(app, sqlalchemy_datastore, get_message):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    authenticate(client)
    sms_sender = setup_tf_sms(client)
    logout(client)

    response = client.get("/login?next=/profile")
    github_url = get_form_action(response, 1)

    response = client.post(github_url, follow_redirects=False)
    assert "/whatever" in response.location
    redirect_url = urllib.parse.urlsplit(urllib.parse.unquote(response.location))
    local_redirect = urllib.parse.parse_qs(redirect_url.query)["redirect_uri"][0]

    response = client.get(local_redirect, follow_redirects=True)
    sendcode_url = get_form_action(response, 0)

    response = client.post(
        sendcode_url,
        data=dict(code=sms_sender.messages[0].split()[-1]),
        follow_redirects=True,
    )
    assert b"Profile Page" in response.data


@pytest.mark.settings(
    oauth_enable=True,
    redirect_host="myui.com:8090",
    redirect_behavior="spa",
    login_error_view="/login-error",
    post_oauth_login_view="/post-login",
    csrf_ignore_unauth_endpoints=False,
)
@pytest.mark.app_settings(wtf_csrf_enabled=True)
def test_spa(app, sqlalchemy_datastore, get_message):
    CSRFProtect(app)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    csrf_token = get_csrf_token(client)
    headers["X-CSRF-Token"] = csrf_token

    response = client.post("/login/oauthstart/github", headers=headers)
    assert "/whatever" in response.location
    redirect_url = urllib.parse.urlsplit(urllib.parse.unquote(response.location))
    local_redirect = urllib.parse.parse_qs(redirect_url.query)["redirect_uri"][0]

    response = client.get(local_redirect, headers=headers)
    assert response.status_code in [302, 303]

    split = urlsplit(response.location)
    assert "myui.com:8090" == split.netloc
    assert "/post-login" == split.path
    qparams = dict(parse_qsl(split.query))
    assert qparams["email"] == "matt@lp.com"

    # try unknown user - should redirect to login_error_view
    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.github.set_identity("jwag@lp.com")
    response = client.get("/login/oauthresponse/github", follow_redirects=False)
    split = urlsplit(response.location)
    assert "/login-error" == split.path
    qparams = dict(parse_qsl(split.query))
    assert (
        qparams["error"]
        == get_message("IDENTITY_NOT_REGISTERED", id="jwag@lp.com").decode()
    )

    # try fake oauth exception
    from authlib.integrations.base_client.errors import MismatchingStateError

    oauth_app.github.set_exception(MismatchingStateError)
    response = client.get("/login/oauthresponse/github", follow_redirects=False)
    split = urlsplit(response.location)
    assert "/login-error" == split.path
    qparams = dict(parse_qsl(split.query))
    msg = get_message(
        "OAUTH_HANDSHAKE_ERROR",
        exerror="mismatching_state",
        exdesc="CSRF Warning! State not equal in request and response.",
    )
    assert qparams["error"] == msg.decode()


@pytest.mark.settings(oauth_enable=True, post_login_view="/post-login")
def test_already_auth(app, sqlalchemy_datastore, get_message):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    authenticate(client)
    assert is_authenticated(client, get_message)

    # json
    response = client.post("/login/oauthstart/github", headers=headers)
    assert response.status_code == 400

    # forms
    response = client.post("/login/oauthstart/github", follow_redirects=False)
    assert response.status_code in [302, 303]
    check_location(app, response.location, "/post-login")


@pytest.mark.settings(oauth_enable=True, post_login_view="/post-login")
def test_simple_next(app, sqlalchemy_datastore, get_message):
    # For oauth we stash 'next' in the session since we can't really
    # send it all around the oauth providers.
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    response = client.get("/profile", follow_redirects=True)
    github_url = get_form_action(response, 1)

    response = client.post(github_url, follow_redirects=False)
    assert "/whatever" in response.location
    session = get_session(response)
    assert "fs_oauth_next" in session

    response = client.get("/login/oauthresponse/github", follow_redirects=False)
    assert response.status_code in [302, 303]
    assert check_location(app, response.location, "/profile")
    session = get_session(response)
    assert "fs_oauth_next" not in session


@pytest.mark.settings(oauth_enable=True, post_login_view="/post_login")
def test_provider_class(app, sqlalchemy_datastore, get_message):
    from authlib.integrations.base_client.errors import MismatchingStateError

    class MyOauthProvider(FsOAuthProvider):
        def fetch_identity_cb(self, oauth, token):
            resp = oauth.myoauth.get("user", token=token)
            profile = resp.json()
            return "email", profile["email"]

        def oauth_response_failure(self, error_view, e):
            assert isinstance(e, MismatchingStateError)
            return redirect("/uh-oh")

    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    # Have to register with Oauthglue.
    app.security.oauthglue.register_provider_ext(MyOauthProvider("myoauth"))

    client = app.test_client()
    response = client.get("/login")
    myoauth_url = get_form_action(response, 2)

    response = client.post(myoauth_url, follow_redirects=False)
    assert "/whatever" in response.location

    # test error - and that our handler is called
    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.myoauth.set_exception(MismatchingStateError)
    response = client.get("/login/oauthresponse/myoauth", follow_redirects=False)
    assert response.status_code in [302, 303]
    assert check_location(app, response.location, "/uh-oh")

    # now log in successfully
    oauth_app.myoauth.set_exception(None)

    response = client.get("/login/oauthresponse/myoauth", follow_redirects=False)
    assert response.status_code in [302, 303]
    assert check_location(app, response.location, "/post_login")
    assert is_authenticated(client, get_message)


@pytest.mark.settings(oauth_enable=True, post_verify_view="/post_verify")
def test_verify(app, sqlalchemy_datastore, get_message):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()

    # just authenticate using github
    client.get("/login/oauthresponse/github", follow_redirects=False)
    assert is_authenticated(client, get_message)

    reset_fresh(client, app.config["SECURITY_FRESHNESS"])
    # This will return the /verify form
    response = client.get("/fresh", follow_redirects=True)
    github_url = get_form_action(response, 1)
    assert "oauth-verify-start" in github_url
    response = client.post(github_url, follow_redirects=False)
    assert "/whatever" in response.location
    session = get_session(response)
    assert "fs_oauth_next" in session

    with capture_flashes() as flashes:
        response = client.get(
            "/login/oauth-verify-response/github", follow_redirects=True
        )
    assert flashes[0]["category"] == "info"
    assert flashes[0]["message"].encode("utf-8") == get_message(
        "REAUTHENTICATION_SUCCESSFUL"
    )
    assert b"Fresh Only" in response.data
    session = get_session(response)
    assert "fs_oauth_next" not in session


@pytest.mark.settings(oauth_enable=True)
def test_verify_unknown_user(app, sqlalchemy_datastore, get_message):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    authenticate(client)
    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.github.set_identity("jwag@lp.com")  # this will cause response to fail

    reset_fresh(client, app.config["SECURITY_FRESHNESS"])
    response = client.get("/fresh", follow_redirects=True)
    github_url = get_form_action(response, 1)
    response = client.post(github_url, follow_redirects=False)

    with capture_flashes() as flashes:
        redirect_url = urllib.parse.urlsplit(urllib.parse.unquote(response.location))
        local_redirect = urllib.parse.parse_qs(redirect_url.query)["redirect_uri"][0]
        response = client.get(local_redirect, follow_redirects=True)
    assert flashes[0]["category"] == "error"
    assert flashes[0]["message"].encode("utf-8") == get_message(
        "IDENTITY_NOT_REGISTERED", id="jwag@lp.com"
    )
    assert b"Reauthenticate" in response.data
    session = get_session(response)
    assert "fs_oauth_next" not in session


@pytest.mark.settings(oauth_enable=True)
def test_verify_evil_user(app, sqlalchemy_datastore, get_message):
    # Ensure a valid (evil) user can't use their oauth credentials to 'verify'
    # another user.
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    authenticate(client)  # authenticate as matt@lp.com
    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.github.set_identity("joe@lp.com")  # a valid user

    reset_fresh(client, app.config["SECURITY_FRESHNESS"])
    response = client.get("/fresh", follow_redirects=True)
    github_url = get_form_action(response, 1)
    response = client.post(github_url, follow_redirects=False)

    with capture_flashes() as flashes:
        redirect_url = urllib.parse.urlsplit(urllib.parse.unquote(response.location))
        local_redirect = urllib.parse.parse_qs(redirect_url.query)["redirect_uri"][0]
        response = client.get(local_redirect, follow_redirects=True)
    assert flashes[0]["category"] == "error"
    assert flashes[0]["message"].encode("utf-8") == get_message(
        "IDENTITY_NOT_REGISTERED", id="joe@lp.com"
    )
    assert b"Reauthenticate" in response.data
    session = get_session(response)
    assert "fs_oauth_next" not in session


@pytest.mark.settings(
    oauth_enable=True,
    oauth_builtin_providers=["github"],
    post_oauth_verify_view="/post_oauth_verify",
    redirect_host="myui.com:8090",
    redirect_behavior="spa",
)
def test_verify_spa(app, sqlalchemy_datastore, get_message):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    json_authenticate(client)

    reset_fresh(client, app.config["SECURITY_FRESHNESS"])
    response = client.get("/fresh", headers=headers)
    assert response.json["response"]["reauth_required"]
    assert response.json["response"]["oauth_enabled"]
    assert response.json["response"]["oauth_providers"] == ["github"]

    response = client.post("/login/oauth-verify-start/github", follow_redirects=False)
    assert "/whatever" in response.location

    # this is what github would call
    response = client.get("/login/oauth-verify-response/github", follow_redirects=False)
    assert (
        response.headers["Location"] == "//myui.com:8090/post_oauth_verify?"
        "email=matt%40lp.com&identity=matt%40lp.com"
    )

    response = client.get("/verify", headers=headers)
    assert response.json["response"]["oauth_enabled"]
    assert response.json["response"]["oauth_providers"] == ["github"]


@pytest.mark.settings(
    oauth_enable=True, redirect_behavior="spa", verify_error_view="/verify-error"
)
def test_verify_unknown_user_spa(app, sqlalchemy_datastore, get_message):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    json_authenticate(client)

    reset_fresh(client, app.config["SECURITY_FRESHNESS"])
    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.github.set_identity("jwag@lp.com")

    # what github would have called
    response = client.get("/login/oauth-verify-response/github")
    assert "/verify-error" in response.location
    assert "not+registered" in response.location


@pytest.mark.settings(
    oauth_enable=True, redirect_behavior="spa", verify_error_view="/verify-error"
)
def test_verify_spa_exc(app, sqlalchemy_datastore, get_message):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    json_authenticate(client)
    # try fake oauth exception
    from authlib.integrations.base_client.errors import MismatchingStateError

    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.github.set_exception(MismatchingStateError)
    response = client.get("/login/oauth-verify-response/github", follow_redirects=False)
    split = urlsplit(response.location)
    assert "/verify-error" == split.path
    qparams = dict(parse_qsl(split.query))
    msg = get_message(
        "OAUTH_HANDSHAKE_ERROR",
        exerror="mismatching_state",
        exdesc="CSRF Warning! State not equal in request and response.",
    )
    assert qparams["error"] == msg.decode()


@pytest.mark.two_factor()
@pytest.mark.settings(
    oauth_enable=True,
    redirect_host="myui.com:8090",
    redirect_behavior="spa",
    login_error_view="/login-error",
    post_oauth_login_view="/post-login",
    post_oauth_two_factor_view="/post-oauth-tf",
)
def test_tf_spa_code(app, sqlalchemy_datastore, get_message):
    # OAuth + 2FA in SPA mode redirects to POST_OAUTH_TWO_FACTOR_VIEW with 2FA
    # state in query params (for both browser HTML and JSON Accept headers),
    # and the SPA completes login via /tf-validate.
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    json_authenticate(client)
    sms_sender = setup_tf_sms(client)
    logout(client, headers=headers)

    # Browser redirect callback (Accept: text/html)
    response = client.post("/login/oauthstart/github", follow_redirects=False)
    redirect_url = urllib.parse.urlsplit(urllib.parse.unquote(response.location))
    local_redirect = urllib.parse.parse_qs(redirect_url.query)["redirect_uri"][0]

    response = client.get(
        local_redirect, headers={"Accept": "text/html"}, follow_redirects=False
    )
    assert response.status_code in [302, 303]
    split = urlsplit(response.location)
    assert split.netloc == "myui.com:8090"
    assert split.path == "/post-oauth-tf"
    qparams = dict(parse_qsl(split.query))
    assert qparams["tf_required"] == "1"
    assert qparams["tf_state"] == "ready"
    assert qparams["tf_primary_method"] == "sms"
    assert qparams["tf_method"] == "sms"
    assert qparams["email"] == "matt@lp.com"
    assert qparams["identity"] == "matt@lp.com"

    # Not authenticated until second factor completes
    assert not is_authenticated(client, get_message)

    # Complete 2FA via SPA JSON endpoint
    code = sms_sender.messages[-1].split()[-1]
    response = client.post("/tf-validate", json=dict(code=code), headers=headers)
    assert response.status_code == 200
    assert is_authenticated(client, get_message)

    # Even with Accept: application/json, oauthresponse MUST still redirect
    logout(client, headers=headers)
    response = client.get(
        "/login/oauthresponse/github", headers=headers, follow_redirects=False
    )
    assert response.status_code in [302, 303]
    split = urlsplit(response.location)
    assert split.netloc == "myui.com:8090"
    assert split.path == "/post-oauth-tf"
    qparams = dict(parse_qsl(split.query))
    assert qparams["tf_required"] == "1"
    assert qparams["tf_state"] == "ready"
    assert qparams["tf_method"] == "sms"


@pytest.mark.two_factor()
@pytest.mark.settings(
    oauth_enable=True,
    two_factor_required=True,
    redirect_host="myui.com:8090",
    redirect_behavior="spa",
    login_error_view="/login-error",
    post_oauth_login_view="/post-login",
    post_oauth_two_factor_view="/post-oauth-tf",
)
def test_tf_spa_setup_from_login(app, sqlalchemy_datastore, get_message):
    # When TWO_FACTOR_REQUIRED is True and the user has not set up 2FA yet,
    # OAuth in SPA mode redirects with tf_state=setup_from_login and allows
    # completing setup via /tf-setup + /tf-validate.
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()

    response = client.get("/login/oauthresponse/github", follow_redirects=False)
    assert response.status_code in [302, 303]
    split = urlsplit(response.location)
    assert split.netloc == "myui.com:8090"
    assert split.path == "/post-oauth-tf"
    qparams = dict(parse_qsl(split.query))
    assert qparams["tf_required"] == "1"
    assert qparams["tf_state"] == "setup_from_login"
    assert qparams["email"] == "matt@lp.com"
    assert qparams["identity"] == "matt@lp.com"

    # Complete initial 2FA setup via SPA JSON endpoints
    setup_tf_sms(client)
    assert is_authenticated(client, get_message)


@pytest.mark.two_factor()
@pytest.mark.settings(
    oauth_enable=True,
    sms_service="bad",
    redirect_host="myui.com:8090",
    redirect_behavior="spa",
    login_error_view="/login-error",
    post_oauth_login_view="/post-login",
    post_oauth_two_factor_view="/post-oauth-tf",
)
def test_tf_spa_send_error(app, sqlalchemy_datastore, get_message):
    # If sending the 2FA code fails during SPA OAuth callback, redirect to
    # LOGIN_ERROR_VIEW with the error message and clean up 2FA session state.
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.github.set_identity("gal@lp.com")  # gal already has SMS 2FA

    response = client.get("/login/oauthresponse/github", follow_redirects=False)
    assert response.status_code in [302, 303]
    split = urlsplit(response.location)
    assert split.netloc == "myui.com:8090"
    assert split.path == "/login-error"
    qparams = dict(parse_qsl(split.query))
    assert qparams["error"] == get_message("FAILED_TO_SEND_CODE").decode()
    session_data = get_session(response)
    assert not session_data or "tf_user_id" not in session_data
    assert not session_data or "tf_state" not in session_data


@pytest.mark.two_factor()
@pytest.mark.settings(
    oauth_enable=True,
    redirect_host="myui.com:8090",
    redirect_behavior="spa",
    login_error_view="/login-error",
    post_oauth_login_view="/post-login",
)
def test_tf_spa_no_view_fallback(app, sqlalchemy_datastore, get_message):
    # If POST_OAUTH_TWO_FACTOR_VIEW is not configured in SPA mode, redirect to
    # LOGIN_ERROR_VIEW with tf_required=1 without leaking 2FA session state.
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"oauth": MockAuthlibFlaskClient()}},
    )
    client = app.test_client()
    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.github.set_identity("gal@lp.com")  # gal already has SMS 2FA

    response = client.get("/login/oauthresponse/github", follow_redirects=False)
    assert response.status_code in [302, 303]
    split = urlsplit(response.location)
    assert split.netloc == "myui.com:8090"
    assert split.path == "/login-error"
    qparams = dict(parse_qsl(split.query))
    assert qparams["tf_required"] == "1"
    assert qparams["email"] == "gal@lp.com"
    assert qparams["identity"] == "gal@lp.com"
    assert not is_authenticated(client, get_message)
    session_data = get_session(response)
    assert not session_data or "tf_user_id" not in session_data


@pytest.mark.webauthn()
@pytest.mark.two_factor()
@pytest.mark.settings(
    oauth_enable=True,
    webauthn=True,
    redirect_host="myui.com:8090",
    redirect_behavior="spa",
    login_error_view="/login-error",
    post_oauth_login_view="/post-login",
    post_oauth_two_factor_view="/post-oauth-tf",
)
def test_tf_spa_webauthn_and_select(app, sqlalchemy_datastore, get_message):
    # Verify OAuth + SPA with WebAuthn secondary MFA alone and with multiple
    # MFA methods (tf_select).
    from tests.test_webauthn import (
        HackWebauthnUtil,
        REG_DATA1,
        SIGNIN_DATA1,
        _register_start_json,
    )

    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "security_args": {
                "oauth": MockAuthlibFlaskClient(),
                "webauthn_util_cls": HackWebauthnUtil,
            }
        },
    )
    client = app.test_client()
    json_authenticate(client)

    # Register a secondary WebAuthn credential
    _, response_url = _register_start_json(client, name="sec1", usage="secondary")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200
    logout(client, headers=headers)

    # 1. Single WebAuthn secondary MFA
    response = client.get("/login/oauthresponse/github", follow_redirects=False)
    assert response.status_code in [302, 303]
    split = urlsplit(response.location)
    assert split.netloc == "myui.com:8090"
    assert split.path == "/post-oauth-tf"
    qparams = dict(parse_qsl(split.query))
    assert qparams["tf_required"] == "1"
    assert qparams["tf_state"] == "ready"
    assert qparams["tf_method"] == "webauthn"
    assert qparams["tf_signin_url"] == "/wan-signin"
    assert qparams["email"] == "matt@lp.com"
    assert qparams["identity"] == "matt@lp.com"

    # Complete WebAuthn second factor via SPA JSON endpoints
    response = client.post("/wan-signin", json=dict(), headers=headers)
    assert response.status_code == 200
    assert response.json["response"]["is_secondary"]
    wan_state = response.json["response"]["wan_state"]
    response = client.post(
        f"/wan-signin/{wan_state}",
        json=dict(credential=json.dumps(SIGNIN_DATA1)),
        headers=headers,
    )
    assert response.status_code == 200
    assert is_authenticated(client, get_message)

    # 2. Add SMS 2FA so multiple MFA methods are configured -> tf_select
    sms_sender = setup_tf_sms(client)
    logout(client, headers=headers)

    response = client.get("/login/oauthresponse/github", follow_redirects=False)
    assert response.status_code in [302, 303]
    split = urlsplit(response.location)
    assert split.netloc == "myui.com:8090"
    assert split.path == "/post-oauth-tf"
    qparams = dict(parse_qsl(split.query))
    assert qparams["tf_required"] == "1"
    assert qparams["tf_select"] == "1"
    assert set(qparams["tf_setup_methods"].split(",")) == {"sms", "webauthn"}
    assert qparams["email"] == "matt@lp.com"
    assert qparams["identity"] == "matt@lp.com"

    # Complete selection + SMS 2FA via SPA JSON endpoints
    response = client.post("/tf-select", json=dict(which="sms"), headers=headers)
    assert response.status_code == 200
    assert response.json["response"]["tf_state"] == "ready"
    assert response.json["response"]["tf_method"] == "sms"

    code = sms_sender.messages[-1].split()[-1]
    response = client.post("/tf-validate", json=dict(code=code), headers=headers)
    assert response.status_code == 200
    assert is_authenticated(client, get_message)
