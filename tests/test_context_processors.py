# -*- coding: utf-8 -*-
"""
    test_context_processors
    ~~~~~~~~~~~~~~~~~~~~~~~

    Context processor tests
"""

import pytest
from test_two_factor import tf_authenticate
from test_unified_signin import authenticate as us_authenticate
from utils import authenticate, logout


@pytest.mark.recoverable()
@pytest.mark.registerable()
@pytest.mark.confirmable()
@pytest.mark.changeable()
@pytest.mark.settings(
    login_without_confirmation=True,
    change_password_template="custom_security/change_password.html",
    login_user_template="custom_security/login_user.html",
    reset_password_template="custom_security/reset_password.html",
    forgot_password_template="custom_security/forgot_password.html",
    send_confirmation_template="custom_security/send_confirmation.html",
    register_user_template="custom_security/register_user.html",
)
def test_context_processors(client, app):
    @app.security.context_processor
    def default_ctx_processor():
        return {"global": "global"}

    @app.security.forgot_password_context_processor
    def forgot_password():
        return {"foo": "bar"}

    response = client.get("/reset")
    assert b"global" in response.data
    assert b"bar" in response.data

    @app.security.login_context_processor
    def login():
        return {"foo": "bar"}

    response = client.get("/login")
    assert b"global" in response.data
    assert b"bar" in response.data

    @app.security.register_context_processor
    def register():
        return {"foo": "bar"}

    response = client.get("/register")
    assert b"global" in response.data
    assert b"bar" in response.data

    @app.security.reset_password_context_processor
    def reset_password():
        return {"foo": "bar"}

    response = client.get("/reset")
    assert b"global" in response.data
    assert b"bar" in response.data

    @app.security.change_password_context_processor
    def change_password():
        return {"foo": "bar"}

    authenticate(client)
    response = client.get("/change")
    assert b"global" in response.data
    assert b"bar" in response.data

    @app.security.send_confirmation_context_processor
    def send_confirmation():
        return {"foo": "bar"}

    response = client.get("/confirm")
    assert b"global" in response.data
    assert b"bar" in response.data

    @app.security.mail_context_processor
    def mail():
        return {"foo": "bar"}

    client.get("/logout")

    with app.mail.record_messages() as outbox:
        client.post("/reset", data=dict(email="matt@lp.com"))

    email = outbox[0]
    assert "global" in email.html
    assert "bar" in email.html


@pytest.mark.passwordless()
@pytest.mark.settings(send_login_template="custom_security/send_login.html")
def test_passwordless_login_context_processor(app, client):
    @app.security.send_login_context_processor
    def send_login():
        return {"foo": "bar"}

    response = client.get("/login")
    assert b"bar" in response.data


@pytest.mark.two_factor()
@pytest.mark.settings(
    two_factor_required=True,
    login_user_template="custom_security/login_user.html",
    two_factor_verify_password_template="custom_security/tfc.html",
    two_factor_setup_template="custom_security/tf_setup.html",
    two_factor_verify_code_template="custom_security/tf_verify.html",
)
def test_two_factor_context_processors(client, app):
    # Test two factor context processors
    @app.security.context_processor
    def default_ctx_processor():
        return {"global": "global"}

    @app.security.tf_verify_password_context_processor
    def send_two_factor_confirm():
        return {"foo": "bar"}

    tf_authenticate(app, client)
    response = client.get("/tf-confirm")
    assert b"global" in response.data
    assert b"bar" in response.data
    logout(client)

    @app.security.tf_setup_context_processor
    def send_two_factor_setup():
        return {"foo": "bar"}

    # Note this just does initial login on a user that hasn't setup 2FA yet.
    authenticate(client)
    response = client.get("/tf-setup")
    assert b"global" in response.data
    assert b"bar" in response.data
    logout(client)

    @app.security.tf_token_validation_context_processor
    def send_two_factor_token_validation():
        return {"foo": "bar"}

    tf_authenticate(app, client, validate=False)
    response = client.get("/tf-rescue")
    assert b"global" in response.data
    assert b"bar" in response.data
    logout(client)


@pytest.mark.unified_signin()
@pytest.mark.settings(
    us_setup_template="custom_security/us_setup.html",
    us_signin_template="custom_security/us_signin.html",
)
def test_unified_signin_context_processors(client, app):
    @app.security.context_processor
    def default_ctx_processor():
        return {"global": "global"}

    @app.security.us_signin_context_processor
    def signin_ctx():
        return {"foo": "signin"}

    # signin template is used in 3 places (TODO test POST us-send-code)
    response = client.get("/us-signin")
    assert b"CUSTOM UNIFIED SIGN IN" in response.data
    assert b"global" in response.data
    assert b"signin" in response.data

    response = client.get("/us-send-code")
    assert b"CUSTOM UNIFIED SIGN IN" in response.data
    assert b"global" in response.data
    assert b"signin" in response.data

    @app.security.us_setup_context_processor
    def setup_ctx():
        return {"foo": "setup"}

    us_authenticate(client)
    response = client.get("us-setup")
    assert b"CUSTOM UNIFIED SIGNIN SETUP" in response.data
    assert b"global" in response.data
    assert b"setup" in response.data

    response = client.post("us-setup", data=dict(chosen_method="sms", phone="555-1212"))
    assert b"CUSTOM UNIFIED SIGNIN SETUP" in response.data
    assert b"global" in response.data
    assert b"setup" in response.data
