"""
    test_recoverable
    ~~~~~~~~~~~~~~~~

    Recoverable functionality tests
"""

import re
import time
from urllib.parse import parse_qsl, urlsplit

import pytest
from flask import Flask
from tests.test_utils import (
    authenticate,
    capture_flashes,
    capture_reset_password_requests,
    logout,
)

from flask_security.core import UserMixin
from flask_security.forms import LoginForm
from flask_security.signals import password_reset, reset_password_instructions_sent

pytestmark = pytest.mark.recoverable()


def test_recoverable_flag(app, clients, get_message):
    recorded_resets = []
    recorded_instructions_sent = []

    @password_reset.connect_via(app)
    def on_password_reset(app, user):
        recorded_resets.append(user)

    @reset_password_instructions_sent.connect_via(app)
    def on_instructions_sent(app, user, token):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        assert isinstance(token, str)
        recorded_instructions_sent.append(user)

    # Test the reset view
    response = clients.get("/reset")
    assert b"<h1>Send password reset instructions</h1>" in response.data
    assert re.search(b'<input[^>]*type="email"[^>]*>', response.data)

    # Test submitting email to reset password creates a token and sends email
    with capture_reset_password_requests() as requests:
        with app.mail.record_messages() as outbox:
            response = clients.post(
                "/reset", data=dict(email="joe@lp.com"), follow_redirects=True
            )

    assert len(recorded_instructions_sent) == 1
    assert len(outbox) == 1
    assert response.status_code == 200
    assert get_message("PASSWORD_RESET_REQUEST", email="joe@lp.com") in response.data
    token = requests[0]["token"]

    # Test view for reset token
    response = clients.get("/reset/" + token)
    assert b"<h1>Reset password</h1>" in response.data

    # Test submitting a new password but leave out confirm
    response = clients.post(
        "/reset/" + token, data={"password": "newpassword"}, follow_redirects=True
    )
    assert get_message("PASSWORD_NOT_PROVIDED") in response.data
    assert len(recorded_resets) == 0

    # Test submitting a new password
    response = clients.post(
        "/reset/" + token,
        data={"password": "awesome sunset", "password_confirm": "awesome sunset"},
        follow_redirects=True,
    )

    assert get_message("PASSWORD_RESET") in response.data
    assert len(recorded_resets) == 1

    logout(clients)

    # Test logging in with the new password
    response = authenticate(
        clients, "joe@lp.com", "awesome sunset", follow_redirects=True
    )
    assert b"Welcome joe@lp.com" in response.data

    logout(clients)

    # Test invalid email
    response = clients.post(
        "/reset", data=dict(email="bogus@lp.com"), follow_redirects=True
    )
    assert get_message("USER_DOES_NOT_EXIST") in response.data

    logout(clients)

    # Test invalid token
    response = clients.post(
        "/reset/bogus",
        data={"password": "awesome sunset", "password_confirm": "awesome sunset"},
        follow_redirects=True,
    )
    assert get_message("INVALID_RESET_PASSWORD_TOKEN") in response.data

    # Test mangled token
    token = (
        "WyIxNjQ2MzYiLCIxMzQ1YzBlZmVhM2VhZjYwODgwMDhhZGU2YzU0MzZjMiJd."
        "BZEw_Q.lQyo3npdPZtcJ_sNHVHP103syjM"
        "&url_id=fbb89a8328e58c181ea7d064c2987874bc54a23d"
    )
    response = clients.post(
        "/reset/" + token,
        data={"password": "newpassword", "password_confirm": "newpassword"},
        follow_redirects=True,
    )
    assert get_message("INVALID_RESET_PASSWORD_TOKEN") in response.data


@pytest.mark.confirmable()
@pytest.mark.registerable()
@pytest.mark.settings(requires_confirmation_error_view="/confirm")
def test_requires_confirmation_error_redirect(app, clients):
    data = dict(email="jyl@lp.com", password="awesome sunset")
    clients.post("/register", data=data)

    response = clients.post(
        "/reset", data=dict(email="jyl@lp.com"), follow_redirects=True
    )
    assert b"send_confirmation_form" in response.data
    assert b"jyl@lp.com" in response.data


@pytest.mark.settings()
def test_recoverable_json(app, client, get_message):
    recorded_resets = []
    recorded_instructions_sent = []

    @password_reset.connect_via(app)
    def on_password_reset(app, user):
        recorded_resets.append(user)

    @reset_password_instructions_sent.connect_via(app)
    def on_instructions_sent(app, user, token):
        recorded_instructions_sent.append(user)

    with capture_flashes() as flashes:
        # Test reset password creates a token and sends email
        with capture_reset_password_requests() as requests:
            with app.mail.record_messages() as outbox:
                response = client.post(
                    "/reset",
                    json=dict(email="joe@lp.com"),
                    headers={"Content-Type": "application/json"},
                )
                assert response.headers["Content-Type"] == "application/json"

        assert len(recorded_instructions_sent) == 1
        assert len(outbox) == 1
        assert response.status_code == 200
        token = requests[0]["token"]

        # Test invalid email
        response = client.post(
            "/reset",
            json=dict(email="whoknows@lp.com"),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400
        assert response.json["response"]["errors"]["email"][0].encode(
            "utf-8"
        ) == get_message("USER_DOES_NOT_EXIST")

        # Test submitting a new password but leave out 'confirm'
        response = client.post(
            "/reset/" + token,
            data='{"password": "newpassword"}',
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400
        assert response.json["response"]["errors"]["password_confirm"][0].encode(
            "utf-8"
        ) == get_message("PASSWORD_NOT_PROVIDED")

        # Test submitting a new password
        response = client.post(
            "/reset/" + token + "?include_auth_token",
            json=dict(password="awesome sunset", password_confirm="awesome sunset"),
            headers={"Content-Type": "application/json"},
        )
        assert all(
            k in response.json["response"]["user"]
            for k in ["email", "authentication_token"]
        )
        assert len(recorded_resets) == 1

        # reset automatically logs user in
        logout(client)

        # Test logging in with the new password
        response = client.post(
            "/login?include_auth_token",
            json=dict(email="joe@lp.com", password="awesome sunset"),
            headers={"Content-Type": "application/json"},
        )
        assert all(
            k in response.json["response"]["user"]
            for k in ["email", "authentication_token"]
        )

        logout(client)

        # Use token again - should fail since already have set new password.
        response = client.post(
            "/reset/" + token,
            json=dict(password="newpassword", password_confirm="newpassword"),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400
        assert len(recorded_resets) == 1

        # Test invalid token
        response = client.post(
            "/reset/bogus",
            json=dict(password="newpassword", password_confirm="newpassword"),
            headers={"Content-Type": "application/json"},
        )
        assert response.json["response"]["error"].encode("utf-8") == get_message(
            "INVALID_RESET_PASSWORD_TOKEN"
        )
    assert len(flashes) == 0


def test_recover_invalidates_session(app, client):
    # Make sure that if we reset our password - prior sessions are invalidated.

    other_client = app.test_client()
    authenticate(other_client)
    response = other_client.get("/profile", follow_redirects=True)
    assert b"Profile Page" in response.data

    # use normal client to reset password
    with capture_reset_password_requests() as requests:
        response = client.post(
            "/reset",
            json=dict(email="matt@lp.com"),
            headers={"Content-Type": "application/json"},
        )
        assert response.headers["Content-Type"] == "application/json"

    assert response.status_code == 200
    token = requests[0]["token"]

    # Test submitting a new password
    response = client.post(
        "/reset/" + token + "?include_auth_token",
        json=dict(password="awesome sunset", password_confirm="awesome sunset"),
        headers={"Content-Type": "application/json"},
    )
    assert all(
        k in response.json["response"]["user"]
        for k in ["email", "authentication_token"]
    )

    # try to access protected endpoint with old session - shouldn't work
    response = other_client.get("/profile")
    assert response.status_code == 302
    assert response.headers["Location"] == "http://localhost/login?next=%2Fprofile"


def test_login_form_description(sqlalchemy_app):
    app = sqlalchemy_app()
    with app.test_request_context("/login"):
        login_form = LoginForm()
        expected = '<a href="/reset">Forgot password?</a>'
        assert login_form.password.description == expected


@pytest.mark.settings(reset_password_within="1 milliseconds")
def test_expired_reset_token(client, get_message):
    with capture_reset_password_requests() as requests:
        client.post("/reset", data=dict(email="joe@lp.com"), follow_redirects=True)

    user = requests[0]["user"]
    token = requests[0]["token"]

    time.sleep(1)

    with capture_flashes() as flashes:
        msg = get_message(
            "PASSWORD_RESET_EXPIRED", within="1 milliseconds", email=user.email
        )

        # Test getting reset form with expired token
        response = client.get("/reset/" + token, follow_redirects=True)
        assert msg in response.data

        # Test trying to reset password with expired token
        response = client.post(
            "/reset/" + token,
            data={"password": "newpassword", "password_confirm": "newpassword"},
            follow_redirects=True,
        )

        assert msg in response.data
    assert len(flashes) == 2


def test_bad_reset_token(client, get_message):
    # Test invalid token - get form
    response = client.get("/reset/bogus", follow_redirects=True)
    assert get_message("INVALID_RESET_PASSWORD_TOKEN") in response.data

    # Test invalid token - reset password
    response = client.post(
        "/reset/bogus",
        data={"password": "newpassword", "password_confirm": "newpassword"},
        follow_redirects=True,
    )
    assert get_message("INVALID_RESET_PASSWORD_TOKEN") in response.data

    # Test mangled token
    token = (
        "WyIxNjQ2MzYiLCIxMzQ1YzBlZmVhM2VhZjYwODgwMDhhZGU2YzU0MzZjMiJd."
        "BZEw_Q.lQyo3npdPZtcJ_sNHVHP103syjM"
        "&url_id=fbb89a8328e58c181ea7d064c2987874bc54a23d"
    )
    response = client.post(
        "/reset/" + token,
        data={"password": "newpassword", "password_confirm": "newpassword"},
        follow_redirects=True,
    )
    assert get_message("INVALID_RESET_PASSWORD_TOKEN") in response.data


def test_reset_token_deleted_user(app, client, get_message, sqlalchemy_datastore):
    with capture_reset_password_requests() as requests:
        client.post("/reset", data=dict(email="gene@lp.com"), follow_redirects=True)

    token = requests[0]["token"]

    # Delete user
    with app.app_context():
        # load user (and role) to get into session so cascade delete works.
        user = app.security.datastore.find_user(email="gene@lp.com")
        sqlalchemy_datastore.delete(user)
        sqlalchemy_datastore.commit()

    response = client.post(
        "/reset/" + token,
        data={"password": "newpassword", "password_confirm": "newpassword"},
        follow_redirects=True,
    )

    msg = get_message("INVALID_RESET_PASSWORD_TOKEN")
    assert msg in response.data


def test_used_reset_token(client, get_message):
    with capture_reset_password_requests() as requests:
        client.post("/reset", data=dict(email="joe@lp.com"), follow_redirects=True)

    token = requests[0]["token"]

    # use the token
    response = client.post(
        "/reset/" + token,
        data={"password": "awesome sunset", "password_confirm": "awesome sunset"},
        follow_redirects=True,
    )

    assert get_message("PASSWORD_RESET") in response.data

    logout(client)

    # attempt to use it a second time
    response2 = client.post(
        "/reset/" + token,
        data={"password": "otherpassword", "password_confirm": "otherpassword"},
        follow_redirects=True,
    )

    msg = get_message("INVALID_RESET_PASSWORD_TOKEN")
    assert msg in response2.data


def test_reset_passwordless_user(client, get_message):
    with capture_reset_password_requests() as requests:
        client.post("/reset", data=dict(email="jess@lp.com"), follow_redirects=True)

    token = requests[0]["token"]

    # use the token
    response = client.post(
        "/reset/" + token,
        data={"password": "awesome sunset", "password_confirm": "awesome sunset"},
        follow_redirects=True,
    )

    assert get_message("PASSWORD_RESET") in response.data


@pytest.mark.settings(reset_url="/custom_reset")
def test_custom_reset_url(client):
    response = client.get("/custom_reset")
    assert response.status_code == 200


@pytest.mark.settings(
    reset_password_template="custom_security/reset_password.html",
    forgot_password_template="custom_security/forgot_password.html",
)
def test_custom_reset_templates(client):
    response = client.get("/reset")
    assert b"CUSTOM FORGOT PASSWORD" in response.data

    with capture_reset_password_requests() as requests:
        client.post("/reset", data=dict(email="joe@lp.com"), follow_redirects=True)
        token = requests[0]["token"]

    response = client.get("/reset/" + token)
    assert b"CUSTOM RESET PASSWORD" in response.data


@pytest.mark.settings(
    redirect_host="localhost:8081",
    redirect_behavior="spa",
    reset_view="/reset-redirect",
)
def test_spa_get(app, client):
    """
    Test 'single-page-application' style redirects
    This uses json only.
    """
    with capture_reset_password_requests() as requests:
        response = client.post(
            "/reset",
            json=dict(email="joe@lp.com"),
            headers={"Content-Type": "application/json"},
        )
        assert response.headers["Content-Type"] == "application/json"
        assert "user" not in response.json["response"]
    token = requests[0]["token"]

    response = client.get("/reset/" + token)
    assert response.status_code == 302
    split = urlsplit(response.headers["Location"])
    assert "localhost:8081" == split.netloc
    assert "/reset-redirect" == split.path
    qparams = dict(parse_qsl(split.query))
    assert qparams["email"] == "joe@lp.com"
    assert qparams["token"] == token


@pytest.mark.settings(
    reset_password_within="1 milliseconds",
    redirect_host="localhost:8081",
    redirect_behavior="spa",
    reset_error_view="/reset-error",
)
def test_spa_get_bad_token(app, client, get_message):
    """ Test expired and invalid token"""
    with capture_flashes() as flashes:
        with capture_reset_password_requests() as requests:
            response = client.post(
                "/reset",
                json=dict(email="joe@lp.com"),
                headers={"Content-Type": "application/json"},
            )
            assert response.headers["Content-Type"] == "application/json"
            assert "user" not in response.json["response"]
        token = requests[0]["token"]
        time.sleep(1)

        response = client.get("/reset/" + token)
        assert response.status_code == 302
        split = urlsplit(response.headers["Location"])
        assert "localhost:8081" == split.netloc
        assert "/reset-error" == split.path
        qparams = dict(parse_qsl(split.query))
        assert all(k in qparams for k in ["email", "error", "identity"])

        msg = get_message(
            "PASSWORD_RESET_EXPIRED", within="1 milliseconds", email="joe@lp.com"
        )
        assert msg == qparams["error"].encode("utf-8")

        # Test mangled token
        token = (
            "WyIxNjQ2MzYiLCIxMzQ1YzBlZmVhM2VhZjYwODgwMDhhZGU2YzU0MzZjMiJd."
            "BZEw_Q.lQyo3npdPZtcJ_sNHVHP103syjM"
            "&url_id=fbb89a8328e58c181ea7d064c2987874bc54a23d"
        )
        response = client.get("/reset/" + token)
        assert response.status_code == 302
        split = urlsplit(response.headers["Location"])
        assert "localhost:8081" == split.netloc
        assert "/reset-error" == split.path
        qparams = dict(parse_qsl(split.query))
        assert len(qparams) == 1
        assert all(k in qparams for k in ["error"])

        msg = get_message("INVALID_RESET_PASSWORD_TOKEN")
        assert msg == qparams["error"].encode("utf-8")
    assert len(flashes) == 0


@pytest.mark.settings(password_complexity_checker="zxcvbn")
def test_easy_password(client, get_message):
    with capture_reset_password_requests() as requests:
        client.post("/reset", data=dict(email="joe@lp.com"), follow_redirects=True)

    token = requests[0]["token"]

    # use the token
    response = client.post(
        "/reset/" + token,
        data={"password": "mypassword", "password_confirm": "mypassword"},
        follow_redirects=True,
    )

    assert b"This is a very common password" in response.data


def test_reset_inactive(client, get_message):
    response = client.post(
        "/reset", data=dict(email="tiya@lp.com"), follow_redirects=True
    )
    assert get_message("DISABLED_ACCOUNT") in response.data

    response = client.post(
        "/reset",
        json=dict(email="tiya@lp.com"),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400


def test_email_normalization(client, get_message):
    response = client.post(
        "/reset", data=dict(email="joe@LP.COM"), follow_redirects=True
    )
    assert response.status_code == 200
    assert get_message("PASSWORD_RESET_REQUEST", email="joe@lp.com") in response.data
