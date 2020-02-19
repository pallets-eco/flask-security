# -*- coding: utf-8 -*-
"""
    test_registerable
    ~~~~~~~~~~~~~~~~~

    Registerable tests
"""

import pytest
from flask import Flask
from utils import authenticate, logout

from flask_security import Security
from flask_security.core import UserMixin
from flask_security.forms import ConfirmRegisterForm, RegisterForm, StringField
from flask_security.signals import user_registered

pytestmark = pytest.mark.registerable()


@pytest.mark.settings(post_register_view="/post_register")
def test_registerable_flag(client, app, get_message):
    recorded = []

    # Test the register view
    response = client.get("/register")
    assert b"<h1>Register</h1>" in response.data

    # Test registering is successful, sends email, and fires signal
    @user_registered.connect_via(app)
    def on_user_registered(app, user, confirm_token, form_data):

        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        assert confirm_token is None
        assert len(form_data.keys()) > 0

        recorded.append(user)

    data = dict(
        email="dude@lp.com",
        password="battery staple",
        password_confirm="battery staple",
        next="",
    )
    with app.mail.record_messages() as outbox:
        response = client.post("/register", data=data, follow_redirects=True)

    assert len(recorded) == 1
    assert len(outbox) == 1
    assert b"Post Register" in response.data

    logout(client)

    # Test user can login after registering
    response = authenticate(client, email="dude@lp.com", password="battery staple")
    assert response.status_code == 302

    logout(client)

    # Test registering with an existing email
    data = dict(
        email="dude@lp.com", password="password", password_confirm="password", next=""
    )
    response = client.post("/register", data=data, follow_redirects=True)
    assert get_message("EMAIL_ALREADY_ASSOCIATED", email="dude@lp.com") in response.data

    # Test registering with an existing email but case insensitive
    data = dict(
        email="Dude@lp.com", password="password", password_confirm="password", next=""
    )
    response = client.post("/register", data=data, follow_redirects=True)
    assert get_message("EMAIL_ALREADY_ASSOCIATED", email="Dude@lp.com") in response.data

    # Test registering with JSON
    data = dict(email="dude2@lp.com", password="horse battery")
    response = client.post(
        "/register", json=data, headers={"Content-Type": "application/json"}
    )

    assert response.headers["content-type"] == "application/json"
    assert response.json["meta"]["code"] == 200
    assert len(response.json["response"]) == 2
    assert all(k in response.json["response"] for k in ["csrf_token", "user"])

    logout(client)

    # Test registering with invalid JSON
    data = dict(email="bogus", password="password")
    response = client.post(
        "/register", json=data, headers={"Content-Type": "application/json"}
    )
    assert response.headers["content-type"] == "application/json"
    assert response.json["meta"]["code"] == 400

    logout(client)

    # Test ?next param
    data = dict(
        email="dude3@lp.com",
        password="horse staple",
        password_confirm="horse staple",
        next="",
    )

    response = client.post("/register?next=/page1", data=data, follow_redirects=True)
    assert b"Page 1" in response.data


@pytest.mark.confirmable()
def test_required_password(client, get_message):
    # when confirm required - should not require confirm_password - but should
    # require a password
    data = dict(email="trp@lp.com", password="")
    response = client.post("/register", data=data, follow_redirects=True)
    assert get_message("PASSWORD_NOT_PROVIDED") in response.data

    data = dict(email="trp@lp.com", password="battery staple")
    response = client.post("/register", data=data, follow_redirects=True)
    assert get_message("CONFIRM_REGISTRATION", email="trp@lp.com") in response.data


def test_required_password_confirm(client, get_message):
    response = client.post(
        "/register",
        data={
            "email": "trp@lp.com",
            "password": "password",
            "password_confirm": "notpassword",
        },
        follow_redirects=True,
    )
    assert get_message("RETYPE_PASSWORD_MISMATCH") in response.data

    response = client.post(
        "/register",
        data={"email": "trp@lp.com", "password": "password", "password_confirm": ""},
        follow_redirects=True,
    )
    assert get_message("PASSWORD_NOT_PROVIDED") in response.data


@pytest.mark.confirmable()
@pytest.mark.unified_signin()
def test_allow_null_password(client, get_message):
    # If unified sign in is enabled - should be able to register w/o password
    data = dict(email="trp@lp.com", password="")
    response = client.post("/register", data=data, follow_redirects=True)
    assert get_message("CONFIRM_REGISTRATION", email="trp@lp.com") in response.data


@pytest.mark.unified_signin()
def test_allow_null_password_nologin(client, get_message):
    # If unified sign in is enabled - should be able to register w/o password
    # With confirmable false - should be logged in automatically upon register.
    # But shouldn't be able to perform normal login again
    data = dict(email="trp@lp.com", password="")
    response = client.post("/register", data=data, follow_redirects=True)
    assert b"Welcome trp@lp.com" in response.data
    logout(client)

    # Make sure can't log in
    response = authenticate(client, email="trp@lp.com", password="")
    assert get_message("PASSWORD_NOT_PROVIDED") in response.data

    response = authenticate(client, email="trp@lp.com", password="NoPassword")
    assert get_message("INVALID_PASSWORD") in response.data


@pytest.mark.settings(
    register_url="/custom_register", post_register_view="/post_register"
)
def test_custom_register_url(client):
    response = client.get("/custom_register")
    assert b"<h1>Register</h1>" in response.data

    data = dict(
        email="dude@lp.com",
        password="battery staple",
        password_confirm="battery staple",
        next="",
    )

    response = client.post("/custom_register", data=data, follow_redirects=True)
    assert b"Post Register" in response.data


@pytest.mark.settings(register_user_template="custom_security/register_user.html")
def test_custom_register_template(client):
    response = client.get("/register")
    assert b"CUSTOM REGISTER USER" in response.data


@pytest.mark.settings(send_register_email=False)
def test_disable_register_emails(client, app):
    data = dict(
        email="dude@lp.com", password="password", password_confirm="password", next=""
    )
    with app.mail.record_messages() as outbox:
        client.post("/register", data=data, follow_redirects=True)
    assert len(outbox) == 0


@pytest.mark.two_factor()
@pytest.mark.settings(two_factor_required=True)
def test_two_factor(app, client):
    """ If two-factor is enabled, the register shouldn't login, but start the
    2-factor setup.
    """
    data = dict(email="dude@lp.com", password="password", password_confirm="password")
    response = client.post("/register", data=data, follow_redirects=False)
    assert "tf-setup" in response.location

    # make sure not logged in
    response = client.get("/profile")
    assert response.status_code == 302
    assert "/login?next=%2Fprofile" in response.location


@pytest.mark.two_factor()
@pytest.mark.settings(two_factor_required=True)
def test_two_factor_json(app, client, get_message):
    data = dict(email="dude@lp.com", password="password", password_confirm="password")
    response = client.post("/register", content_type="application/json", json=data)
    assert response.status_code == 200
    assert response.json["response"]["tf_required"]
    assert response.json["response"]["tf_state"] == "setup_from_login"

    # make sure not logged in
    response = client.get("/profile", headers={"accept": "application/json"})
    assert response.status_code == 401
    assert response.json["response"]["error"].encode("utf-8") == get_message(
        "UNAUTHENTICATED"
    )


def test_form_data_is_passed_to_user_registered_signal(app, sqlalchemy_datastore):
    class MyRegisterForm(RegisterForm):
        additional_field = StringField("additional_field")

    app.security = Security(
        app, datastore=sqlalchemy_datastore, register_form=MyRegisterForm
    )

    recorded = []

    @user_registered.connect_via(app)
    def on_user_registered(app, user, confirm_token, form_data):

        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        assert confirm_token is None
        assert form_data["additional_field"] == "additional_data"

        recorded.append(user)

    client = app.test_client()

    data = dict(
        email="dude@lp.com",
        password="password",
        password_confirm="password",
        additional_field="additional_data",
    )
    response = client.post("/register", data=data, follow_redirects=True)

    assert response.status_code == 200
    assert len(recorded) == 1


@pytest.mark.settings(password_complexity_checker="zxcvbn")
def test_easy_password(app, sqlalchemy_datastore):
    class MyRegisterForm(ConfirmRegisterForm):
        username = StringField("Username")

    app.config["SECURITY_CONFIRM_REGISTER_FORM"] = MyRegisterForm
    security = Security(datastore=sqlalchemy_datastore)
    security.init_app(app)

    client = app.test_client()

    # With zxcvbn
    data = dict(
        email="dude@lp.com",
        username="dude",
        password="mattmatt2",
        password_confirm="mattmatt2",
    )
    response = client.post(
        "/register", json=data, headers={"Content-Type": "application/json"}
    )
    assert response.headers["Content-Type"] == "application/json"
    assert response.status_code == 400
    # Response from zxcvbn
    assert "Repeats like" in response.json["response"]["errors"]["password"][0]

    # Test that username affects password selection
    data = dict(
        email="dude@lp.com",
        username="Joe",
        password="JoeTheDude",
        password_confirm="JoeTheDude",
    )
    response = client.post(
        "/register", json=data, headers={"Content-Type": "application/json"}
    )
    assert response.headers["Content-Type"] == "application/json"
    assert response.status_code == 400
    # Response from zxcvbn
    assert (
        "Password not complex enough"
        in response.json["response"]["errors"]["password"][0]
    )
