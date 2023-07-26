"""
    test_oauthglue.py
    ~~~~~~~~~~~~~~~~~

    Oauth glue tests - oauthglue is a very thin shim between FS and authlib

    :copyright: (c) 2022-2023 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import pytest
import urllib.parse
from urllib.parse import parse_qsl, urlsplit

from flask import redirect
from flask_wtf import CSRFProtect

from tests.test_utils import (
    authenticate,
    get_csrf_token,
    get_form_action,
    get_form_input,
    init_app_with_options,
    logout,
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


class MockOAuth:
    def __init__(self):
        pass

    def register(self, name, **kwargs):
        setattr(self, name, MockProvider(name))


@pytest.mark.settings(oauth_enable=True, post_login_view="/post_login")
@pytest.mark.app_settings(wtf_csrf_enabled=True)
def test_github(app, sqlalchemy_datastore, get_message):
    CSRFProtect(app)
    init_app_with_options(
        app, sqlalchemy_datastore, **{"security_args": {"oauth": MockOAuth()}}
    )
    client = app.test_client()
    response = client.get("/login")
    github_url = get_form_action(response, 1)
    csrf_token = get_form_input(response, field_id="github_csrf_token")

    # make sure required CSRF
    response = client.post(github_url, follow_redirects=False)
    assert "The CSRF token is missing"

    response = client.post(
        github_url, data=dict(csrf_token=csrf_token), follow_redirects=False
    )
    assert "/whatever" in response.location

    response = client.get("/login/oauthresponse/github", follow_redirects=False)
    assert response.status_code == 302
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
        app, sqlalchemy_datastore, **{"security_args": {"oauth": MockOAuth()}}
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

    authlib_oauth = MockOAuth()
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
    assert response.status_code == 302
    assert "/post_login" in response.location
    # verify logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200


@pytest.mark.settings(oauth_enable=True)
def test_bad_api(app, sqlalchemy_datastore, get_message):
    init_app_with_options(
        app, sqlalchemy_datastore, **{"security_args": {"oauth": MockOAuth()}}
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
    assert get_message("OAUTH_HANDSHAKE_ERROR") in response.data


@pytest.mark.settings(oauth_enable=True)
def test_unknown_user(app, sqlalchemy_datastore, get_message):
    init_app_with_options(
        app, sqlalchemy_datastore, **{"security_args": {"oauth": MockOAuth()}}
    )
    client = app.test_client()
    oauth_app = app.security.oauthglue.oauth_app
    oauth_app.github.set_identity("jwag@lp.com")
    response = client.get("/login/oauthresponse/github", follow_redirects=True)
    assert get_message("IDENTITY_NOT_REGISTERED", id="jwag@lp.com") in response.data


@pytest.mark.two_factor()
@pytest.mark.settings(oauth_enable=True)
def test_tf(app, sqlalchemy_datastore, get_message):
    init_app_with_options(
        app, sqlalchemy_datastore, **{"security_args": {"oauth": MockOAuth()}}
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
    redirect_host="localhost:8081",
    redirect_behavior="spa",
    login_error_view="/login-error",
    post_login_view="/post-login",
    csrf_ignore_unauth_endpoints=False,
)
@pytest.mark.app_settings(wtf_csrf_enabled=True)
def test_spa(app, sqlalchemy_datastore, get_message):
    CSRFProtect(app)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    init_app_with_options(
        app, sqlalchemy_datastore, **{"security_args": {"oauth": MockOAuth()}}
    )
    client = app.test_client()
    csrf_token = get_csrf_token(client)
    headers["X-CSRF-Token"] = csrf_token

    response = client.post("/login/oauthstart/github", headers=headers)
    assert "/whatever" in response.location
    redirect_url = urllib.parse.urlsplit(urllib.parse.unquote(response.location))
    local_redirect = urllib.parse.parse_qs(redirect_url.query)["redirect_uri"][0]

    response = client.get(local_redirect, headers=headers)
    assert response.status_code == 302

    split = urlsplit(response.location)
    assert "localhost:8081" == split.netloc
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
    assert qparams["error"] == get_message("OAUTH_HANDSHAKE_ERROR").decode()
