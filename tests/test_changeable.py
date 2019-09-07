# -*- coding: utf-8 -*-
"""
    test_changeable
    ~~~~~~~~~~~~~~~

    Changeable tests

    :copyright: (c) 2019 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import json

import pytest
from flask import Flask
from utils import authenticate, json_authenticate, verify_token

from flask_security.core import UserMixin
from flask_security.signals import password_changed

pytestmark = pytest.mark.changeable()


def test_changeable_flag(app, client, get_message):
    recorded = []

    @password_changed.connect_via(app)
    def on_password_changed(app, user):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        recorded.append(user)

    authenticate(client)

    # Test change view
    response = client.get("/change", follow_redirects=True)
    assert b"Change password" in response.data

    # Test wrong original password
    response = client.post(
        "/change",
        data={
            "password": "notpassword",
            "new_password": "newpassword",
            "new_password_confirm": "newpassword",
        },
        follow_redirects=True,
    )
    assert get_message("INVALID_PASSWORD") in response.data

    # Test mismatch
    response = client.post(
        "/change",
        data={
            "password": "password",
            "new_password": "newpassword",
            "new_password_confirm": "notnewpassword",
        },
        follow_redirects=True,
    )
    assert get_message("RETYPE_PASSWORD_MISMATCH") in response.data

    # Test missing password
    response = client.post(
        "/change",
        data={"password": "   ", "new_password": "", "new_password_confirm": ""},
        follow_redirects=True,
    )
    assert get_message("PASSWORD_NOT_PROVIDED") in response.data

    # Test bad password
    response = client.post(
        "/change",
        data={"password": "password", "new_password": "a", "new_password_confirm": "a"},
        follow_redirects=True,
    )
    assert get_message("PASSWORD_INVALID_LENGTH") in response.data

    # Test same as previous
    response = client.post(
        "/change",
        data={
            "password": "password",
            "new_password": "password",
            "new_password_confirm": "password",
        },
        follow_redirects=True,
    )
    assert get_message("PASSWORD_IS_THE_SAME") in response.data

    # Test successful submit sends email notification
    with app.mail.record_messages() as outbox:
        response = client.post(
            "/change",
            data={
                "password": "password",
                "new_password": "newpassword",
                "new_password_confirm": "newpassword",
            },
            follow_redirects=True,
        )

    assert get_message("PASSWORD_CHANGE") in response.data
    assert b"Home Page" in response.data
    assert len(recorded) == 1
    assert len(outbox) == 1
    assert "Your password has been changed" in outbox[0].html

    # Test leading & trailing whitespace not stripped
    response = client.post(
        "/change",
        data={
            "password": "newpassword",
            "new_password": "      newpassword      ",
            "new_password_confirm": "      newpassword      ",
        },
        follow_redirects=True,
    )
    assert get_message("PASSWORD_CHANGE") in response.data

    # Test JSON
    data = (
        '{"password": "      newpassword      ", '
        '"new_password": "newpassword2", '
        '"new_password_confirm": "newpassword2"}'
    )
    response = client.post(
        "/change", data=data, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/json"

    # Test JSON errors
    data = '{"password": "newpassword"}'
    response = client.post(
        "/change", data=data, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert response.jdata["response"]["errors"]["new_password"] == [
        "Password not provided"
    ]


@pytest.mark.settings(change_url="/custom_change")
def test_custom_change_url(client):
    authenticate(client)
    response = client.get("/custom_change")
    assert response.status_code == 200


@pytest.mark.settings(change_password_template="custom_security/change_password.html")
def test_custom_change_template(client):
    authenticate(client)
    response = client.get("/change")
    assert b"CUSTOM CHANGE PASSWORD" in response.data


@pytest.mark.settings(send_password_change_email=False)
def test_disable_change_emails(app, client):
    with app.mail.record_messages() as outbox:
        client.post(
            "/change",
            data={
                "password": "password",
                "new_password": "newpassword",
                "new_password_confirm": "newpassword",
            },
            follow_redirects=True,
        )
    assert len(outbox) == 0


@pytest.mark.settings(post_change_view="/profile")
def test_custom_post_change_view(client):
    authenticate(client)
    response = client.post(
        "/change",
        data={
            "password": "password",
            "new_password": "newpassword",
            "new_password_confirm": "newpassword",
        },
        follow_redirects=True,
    )

    assert b"Profile Page" in response.data


def test_token_change(app, client_nc):
    # Verify can change password using token auth only
    login_response = json_authenticate(client_nc)
    token = login_response.jdata["response"]["user"]["authentication_token"]

    data = dict(
        password="password",
        new_password="newpassword",
        new_password_confirm="newpassword",
    )
    response = client_nc.post(
        "/change?include_auth_token=1",
        data=json.dumps(data),
        headers={"Content-Type": "application/json", "Authentication-Token": token},
    )
    assert response.status_code == 200
    assert "authentication_token" in response.jdata["response"]["user"]


@pytest.mark.settings(backwards_compat_auth_token_invalid=True)
def test_bc_password(app, client_nc):
    # Test behavior of BACKWARDS_COMPAT_AUTH_TOKEN_INVALID
    response = json_authenticate(client_nc)
    token = response.jdata["response"]["user"]["authentication_token"]
    verify_token(client_nc, token)

    data = dict(
        password="password",
        new_password="newpassword",
        new_password_confirm="newpassword",
    )
    response = client_nc.post(
        "/change?include_auth_token=1",
        data=json.dumps(data),
        headers={"Content-Type": "application/json", "Authentication-Token": token},
    )
    assert response.status_code == 200
    assert "authentication_token" in response.jdata["response"]["user"]

    # changing password should have rendered existing auth tokens invalid
    verify_token(client_nc, token, status=401)

    # but new auth token should work
    token = response.jdata["response"]["user"]["authentication_token"]
    verify_token(client_nc, token)
