"""
    test_configuration
    ~~~~~~~~~~~~~~~~~~

    Basic configuration tests
"""

import base64

import pytest
from tests.test_utils import authenticate, logout


@pytest.mark.settings(
    logout_url="/custom_logout",
    login_url="/custom_login",
    post_login_view="/post_login",
    post_logout_view="/post_logout",
    default_http_auth_realm="Custom Realm",
)
def test_view_configuration(client):
    response = client.get("/custom_login")
    assert b"<h1>Login</h1>" in response.data

    response = authenticate(client, endpoint="/custom_login")
    assert "location" in response.headers
    assert "/post_login" in response.location

    response = logout(client, endpoint="/custom_logout")
    assert "location" in response.headers
    assert "/post_logout" in response.location

    response = client.get(
        "/http",
        headers={"Authorization": "Basic %s" % base64.b64encode(b"joe@lp.com:bogus")},
    )
    assert response.status_code == 401
    assert b"You are not authenticated" in response.data
    assert "WWW-Authenticate" in response.headers
    assert 'Basic realm="Custom Realm"' == response.headers["WWW-Authenticate"]


@pytest.mark.settings(login_user_template="custom_security/login_user.html")
def test_template_configuration(client):
    response = client.get("/login")
    assert b"CUSTOM LOGIN USER" in response.data
