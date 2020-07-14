"""
    test_passwordless
    ~~~~~~~~~~~~~~~~~

    Passwordless tests
"""

import time
from urllib.parse import parse_qsl, urlsplit

import pytest
from flask import Flask
from tests.test_utils import (
    capture_flashes,
    capture_passwordless_login_requests,
    logout,
)

from flask_security.core import UserMixin
from flask_security.signals import login_instructions_sent

pytestmark = pytest.mark.passwordless()


def test_trackable_flag(app, client, get_message):
    recorded = []

    @login_instructions_sent.connect_via(app)
    def on_instructions_sent(app, user, login_token):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        assert isinstance(login_token, str)
        recorded.append(user)

    # Test disabled account
    response = client.post(
        "/login", data=dict(email="tiya@lp.com"), follow_redirects=True
    )
    assert get_message("DISABLED_ACCOUNT") in response.data

    # Test login with json and valid email
    data = dict(email="matt@lp.com", password="password")
    response = client.post(
        "/login", json=data, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 200
    assert len(recorded) == 1

    # Test login with json and invalid email
    data = dict(email="nobody@lp.com", password="password")
    response = client.post(
        "/login", json=data, headers={"Content-Type": "application/json"}
    )
    assert b"errors" in response.data

    # Test sends email and shows appropriate response
    with capture_passwordless_login_requests() as requests:
        with app.mail.record_messages() as outbox:
            response = client.post(
                "/login", data=dict(email="matt@lp.com"), follow_redirects=True
            )

    assert len(recorded) == 2
    assert len(requests) == 1
    assert len(outbox) == 1
    assert "user" in requests[0]
    assert "login_token" in requests[0]

    user = requests[0]["user"]
    assert get_message("LOGIN_EMAIL_SENT", email=user.email) in response.data

    token = requests[0]["login_token"]
    response = client.get("/login/" + token, follow_redirects=True)
    assert get_message("PASSWORDLESS_LOGIN_SUCCESSFUL") in response.data

    # Test already authenticated
    response = client.get("/login/" + token, follow_redirects=True)
    assert get_message("PASSWORDLESS_LOGIN_SUCCESSFUL") not in response.data

    logout(client)

    # Test invalid token
    response = client.get("/login/bogus", follow_redirects=True)
    assert get_message("INVALID_LOGIN_TOKEN") in response.data

    # Test login request with invalid email
    response = client.post("/login", data=dict(email="bogus@bogus.com"))
    assert get_message("USER_DOES_NOT_EXIST") in response.data


@pytest.mark.settings(login_within="1 milliseconds")
def test_expired_login_token(client, app, get_message):
    e = "matt@lp.com"

    with capture_passwordless_login_requests() as requests:
        client.post("/login", data=dict(email=e), follow_redirects=True)

    token = requests[0]["login_token"]
    user = requests[0]["user"]

    time.sleep(1)

    response = client.get("/login/" + token, follow_redirects=True)
    assert (
        get_message("LOGIN_EXPIRED", within="1 milliseconds", email=user.email)
        in response.data
    )


@pytest.mark.settings(
    redirect_host="localhost:8081",
    redirect_behavior="spa",
    post_login_view="/login-redirect",
)
def test_spa_get(app, client):
    """
    Test 'single-page-application' style redirects
    This uses json only.
    """
    with capture_flashes() as flashes:
        with capture_passwordless_login_requests() as requests:
            response = client.post(
                "/login",
                json=dict(email="matt@lp.com"),
                headers={"Content-Type": "application/json"},
            )
            assert response.headers["Content-Type"] == "application/json"
        token = requests[0]["login_token"]

        response = client.get("/login/" + token)
        assert response.status_code == 302
        split = urlsplit(response.headers["Location"])
        assert "localhost:8081" == split.netloc
        assert "/login-redirect" == split.path
        qparams = dict(parse_qsl(split.query))
        assert qparams["email"] == "matt@lp.com"
    assert len(flashes) == 0


@pytest.mark.settings(
    login_within="1 milliseconds",
    redirect_host="localhost:8081",
    redirect_behavior="spa",
    login_error_view="/login-error",
)
def test_spa_get_bad_token(app, client, get_message):
    """ Test expired and invalid token"""
    with capture_flashes() as flashes:
        with capture_passwordless_login_requests() as requests:
            response = client.post(
                "/login",
                json=dict(email="matt@lp.com"),
                headers={"Content-Type": "application/json"},
            )
            assert response.headers["Content-Type"] == "application/json"
        token = requests[0]["login_token"]
        time.sleep(1)

        response = client.get("/login/" + token)
        assert response.status_code == 302
        split = urlsplit(response.headers["Location"])
        assert "localhost:8081" == split.netloc
        assert "/login-error" == split.path
        qparams = dict(parse_qsl(split.query))
        assert all(k in qparams for k in ["email", "error", "identity"])

        msg = get_message("LOGIN_EXPIRED", within="1 milliseconds", email="matt@lp.com")
        assert msg == qparams["error"].encode("utf-8")

        # Test mangled token
        token = (
            "WyIxNjQ2MzYiLCIxMzQ1YzBlZmVhM2VhZjYwODgwMDhhZGU2YzU0MzZjMiJd."
            "BZEw_Q.lQyo3npdPZtcJ_sNHVHP103syjM"
            "&url_id=fbb89a8328e58c181ea7d064c2987874bc54a23d"
        )
        response = client.get("/login/" + token)
        assert response.status_code == 302
        split = urlsplit(response.headers["Location"])
        assert "localhost:8081" == split.netloc
        assert "/login-error" == split.path
        qparams = dict(parse_qsl(split.query))
        assert len(qparams) == 1
        assert all(k in qparams for k in ["error"])

        msg = get_message("INVALID_LOGIN_TOKEN")
        assert msg == qparams["error"].encode("utf-8")
    assert len(flashes) == 0
