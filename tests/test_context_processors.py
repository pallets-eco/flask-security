"""
test_context_processors
~~~~~~~~~~~~~~~~~~~~~~~

Context processor tests
"""

import pytest
from tests.test_two_factor import tf_authenticate
from tests.test_unified_signin import authenticate as us_authenticate
from tests.test_utils import authenticate, capture_reset_password_requests, logout


@pytest.mark.recoverable()
@pytest.mark.registerable()
@pytest.mark.confirmable()
@pytest.mark.changeable()
@pytest.mark.change_email()
@pytest.mark.username_recovery()
@pytest.mark.change_username()
@pytest.mark.settings(
    login_without_confirmation=True,
    change_email_template="custom_security/change_email.html",
    change_password_template="custom_security/change_password.html",
    login_user_template="custom_security/login_user.html",
    reset_password_template="custom_security/reset_password.html",
    forgot_password_template="custom_security/forgot_password.html",
    send_confirmation_template="custom_security/send_confirmation.html",
    register_user_template="custom_security/register_user.html",
    verify_template="custom_security/verify.html",
    username_recovery_template="custom_security/recover_username.html",
    change_username_template="custom_security/change_username.html",
)
def test_context_processors(client, app):
    @app.security.context_processor
    def default_ctx_processor():
        return {"global": "global"}

    @app.security.forgot_password_context_processor
    def forgot_password():
        return {"foo": "bar-forgot"}

    response = client.get("/reset")
    assert b"global" in response.data
    assert b"bar-forgot" in response.data

    @app.security.login_context_processor
    def login():
        return {"foo": "bar-login"}

    response = client.get("/login")
    assert b"global" in response.data
    assert b"bar-login" in response.data

    @app.security.verify_context_processor
    def verify():
        return {"foo": "bar-verify"}

    authenticate(client)
    response = client.get("/verify")
    assert b"CUSTOM VERIFY USER" in response.data
    assert b"global" in response.data
    assert b"bar-verify" in response.data
    logout(client)

    @app.security.register_context_processor
    def register():
        return {"foo": "bar-register"}

    response = client.get("/register")
    assert b"global" in response.data
    assert b"bar-register" in response.data

    @app.security.reset_password_context_processor
    def reset_password():
        return {"foo": "bar-reset"}

    # /reset/token - need to generate a token
    with capture_reset_password_requests() as requests:
        response = client.post(
            "/reset", data=dict(email="joe@lp.com"), follow_redirects=True
        )
    token = requests[0]["token"]
    response = client.get(f"/reset/{token}")
    assert b"global" in response.data
    assert b"bar-reset" in response.data

    @app.security.change_password_context_processor
    def change_password():
        return {"foo": "bar-change"}

    authenticate(client)
    response = client.get("/change")
    assert b"global" in response.data
    assert b"bar-change" in response.data

    @app.security.send_confirmation_context_processor
    def send_confirmation():
        return {"foo": "bar-confirm"}

    response = client.get("/confirm")
    assert b"global" in response.data
    assert b"bar-confirm" in response.data

    @app.security.mail_context_processor
    def mail():
        return {"foo": "bar-mail"}

    client.get("/logout")

    client.post("/reset", data=dict(email="matt@lp.com"))

    email = app.mail.outbox[1]
    assert "global" in email.body
    assert "bar-mail" in email.body

    @app.security.change_email_context_processor
    def change_email():
        return {"foo": "bar-change-email"}

    authenticate(client)
    response = client.get("/change-email")
    assert b"global" in response.data
    assert b"bar-change-email" in response.data

    @app.security.recover_username_context_processor
    def recover_username():
        return {"foo": "bar-recover-username"}

    client.get("/logout")
    response = client.get("/recover-username")
    assert b"global" in response.data
    assert b"bar-recover-username" in response.data

    @app.security.change_username_context_processor
    def change_username():
        return {"foo": "bar-change-username"}

    authenticate(client)
    response = client.get("/change-username")
    assert b"global" in response.data
    assert b"bar-change-username" in response.data


@pytest.mark.passwordless()
@pytest.mark.settings(send_login_template="custom_security/send_login.html")
def test_passwordless_login_context_processor(app, client):
    @app.security.send_login_context_processor
    def send_login():
        return {"foo": "bar-send-login"}

    response = client.get("/login")
    assert b"bar-send-login" in response.data


@pytest.mark.two_factor()
@pytest.mark.settings(
    two_factor_required=True,
    login_user_template="custom_security/login_user.html",
    two_factor_setup_template="custom_security/tf_setup.html",
    two_factor_verify_code_template="custom_security/tf_verify.html",
)
def test_two_factor_context_processors(client, app):
    # Test two factor context processors
    @app.security.context_processor
    def default_ctx_processor():
        return {"global": "global"}

    @app.security.tf_setup_context_processor
    def send_two_factor_setup():
        return {"foo": "bar-tfsetup"}

    # Note this just does initial login on a user that hasn't setup 2FA yet.
    authenticate(client)
    response = client.get("/tf-setup")
    assert b"global" in response.data
    assert b"bar-tfsetup" in response.data
    logout(client)

    @app.security.tf_token_validation_context_processor
    def send_two_factor_token_validation():
        return {"foo": "bar-tfvalidate"}

    tf_authenticate(app, client, validate=False)
    response = client.get("/tf-rescue")
    assert b"global" in response.data
    assert b"bar-tfvalidate" in response.data
    logout(client)


@pytest.mark.unified_signin()
@pytest.mark.settings(
    us_setup_template="custom_security/us_setup.html",
    us_signin_template="custom_security/us_signin.html",
    us_verify_template="custom_security/us_verify.html",
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

    response = client.post("/us-signin/send-code")
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

    @app.security.us_verify_context_processor
    def verify_ctx():
        return {"foo": "setup"}

    us_authenticate(client)
    response = client.get("us-verify")
    assert b"CUSTOM UNIFIED VERIFY" in response.data
    assert b"global" in response.data
    assert b"setup" in response.data

    response = client.post(
        "us-verify", data=dict(chosen_method="sms", phone="555-1212")
    )
    assert b"CUSTOM UNIFIED VERIFY" in response.data
    assert b"global" in response.data
    assert b"setup" in response.data


@pytest.mark.two_factor()
@pytest.mark.settings(
    multi_factor_recovery_template="custom_security/mf_recovery.html",
    multi_factor_recovery_codes_template="custom_security/mf_recovery_codes.html",
    multi_factor_recovery_codes=True,
)
def test_mf_recovery_context_processors(client, app):
    @app.security.context_processor
    def default_ctx_processor():
        return {"global": "global"}

    @app.security.mf_recovery_codes_context_processor
    def codes_ctx():
        return {"foo": "codes"}

    authenticate(client)
    response = client.get("/mf-recovery-codes")
    assert b"global" in response.data
    assert b"codes" in response.data
    logout(client)

    @app.security.mf_recovery_context_processor
    def code_ctx():
        return {"foo": "code"}

    authenticate(client, "gal@lp.com")
    response = client.get("/mf-recovery")
    assert b"global" in response.data
    assert b"code" in response.data
