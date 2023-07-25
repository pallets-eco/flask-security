"""
    test_unified_signin
    ~~~~~~~~~~~~~~~~~~~

    Unified signin tests

    :copyright: (c) 2019-2023 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

"""

import base64
from contextlib import contextmanager
from datetime import timedelta
from passlib.totp import TOTP
import re
from urllib.parse import parse_qsl, urlsplit

import pytest
from flask import Flask
from tests.test_utils import (
    SmsBadSender,
    SmsTestSender,
    FakeSerializer,
    authenticate,
    capture_flashes,
    capture_reset_password_requests,
    get_form_action,
    is_authenticated,
    logout,
    reset_fresh,
    setup_tf_sms,
)
from tests.test_webauthn import HackWebauthnUtil, reg_2_keys

from flask_security import (
    SmsSenderFactory,
    SQLAlchemyUserDatastore,
    UserMixin,
    uia_email_mapper,
    uia_phone_mapper,
    us_profile_changed,
    us_security_token_sent,
    user_authenticated,
)

from flask_security.utils import get_identity_attributes

pytestmark = pytest.mark.unified_signin()

SmsSenderFactory.senders["test"] = SmsTestSender
SmsSenderFactory.senders["bad"] = SmsBadSender

UIA_EMAIL_PHONE = [
    {"email": {"mapper": uia_email_mapper, "case_insensitive": True}},
    {"us_phone_number": {"mapper": uia_phone_mapper}},
]


@contextmanager
def capture_send_code_requests():
    login_requests = []

    def _on(app, **data):
        assert isinstance(app, Flask)
        assert all(v in data for v in ["user", "method", "token"])
        assert isinstance(data["user"], UserMixin)
        login_requests.append(data)

    us_security_token_sent.connect(_on)

    try:
        yield login_requests
    finally:
        us_security_token_sent.disconnect(_on)


def us_authenticate(client, identity="matt@lp.com"):
    with capture_send_code_requests() as requests:
        response = client.post(
            "/us-signin/send-code",
            json=dict(identity=identity, chosen_method="email"),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 200

    response = client.post(
        "/us-signin?include_auth_token",
        json=dict(identity=identity, passcode=requests[0]["token"]),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    return response.json["response"]["user"]["authentication_token"]


def us_tf_authenticate(app, client, json=False, validate=True, remember=False):
    """Login/Authenticate using two factor and unified signin
    This is the equivalent of utils:authenticate
    """
    prev_sms = app.config["SECURITY_SMS_SERVICE"]
    app.config["SECURITY_SMS_SERVICE"] = "test"
    sms_sender = SmsSenderFactory.createSender("test")
    json_data = dict(identity="gal@lp.com", passcode="password", remember=remember)
    response = client.post(
        "/us-signin", json=json_data, headers={"Content-Type": "application/json"}
    )

    assert b'"code": 200' in response.data
    app.config["SECURITY_SMS_SERVICE"] = prev_sms

    if validate:
        code = sms_sender.messages[0].split()[-1]
        if json:
            response = client.post(
                "/tf-validate",
                json=dict(code=code),
                headers={"Content-Type": "application/json"},
            )
            assert b'"code": 200' in response.data
        else:
            response = client.post(
                "/tf-validate", data=dict(code=code), follow_redirects=True
            )
            assert response.status_code == 200


def set_phone(app, email="matt@lp.com", phone="650-273-3780"):
    # A quick way to 'setup' SMS
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email=email)
        totp_secret = app.security._totp_factory.generate_totp_secret()
        app.security.datastore.us_set(user, "sms", totp_secret, phone)
        app.security.datastore.commit()


def set_email(app, email="matt@lp.com"):
    # A quick way to 'setup' email
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email=email)
        totp_secret = app.security._totp_factory.generate_totp_secret()
        app.security.datastore.us_set(user, "email", totp_secret)
        app.security.datastore.commit()


def test_simple_signin(app, clients, get_message):
    set_email(app)
    auths = []

    @user_authenticated.connect_via(app)
    def authned(myapp, user, **extra_args):
        auths.append((user.email, extra_args["authn_via"]))

    # Test missing choice
    data = dict(identity="matt@lp.com")
    response = clients.post("/us-signin/send-code", data=data, follow_redirects=True)
    assert get_message("US_METHOD_NOT_AVAILABLE") in response.data

    # Test login using invalid email
    data = dict(identity="nobody@lp.com", chosen_method="email")
    response = clients.post("/us-signin/send-code", data=data, follow_redirects=True)
    assert get_message("US_SPECIFY_IDENTITY") in response.data

    # test disabled account
    set_email(app, email="gal3@lp.com")
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="gal3@lp.com")
        app.security.datastore.deactivate_user(user)
        app.security.datastore.commit()

    data = dict(identity="gal3@lp.com", chosen_method="email")
    response = clients.post("/us-signin/send-code", data=data, follow_redirects=True)
    assert b"Code has been sent" not in response.data
    assert get_message("DISABLED_ACCOUNT") in response.data

    with capture_send_code_requests() as requests:
        response = clients.post(
            "/us-signin/send-code",
            data=dict(identity="matt@lp.com", chosen_method="email"),
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Sign In" in response.data
    assert len(requests) == 1
    assert len(app.mail.outbox) == 1

    # try bad code
    response = clients.post(
        "/us-signin",
        data=dict(identity="matt@lp.com", passcode="blahblah"),
        follow_redirects=True,
    )
    assert get_message("INVALID_PASSWORD_CODE") in response.data

    # Correct code
    assert not clients.get_cookie("remember_token")
    assert not clients.get_cookie("session")
    response = clients.post(
        "/us-signin",
        data=dict(identity="matt@lp.com", passcode=requests[0]["token"]),
        follow_redirects=False,
    )
    assert not clients.get_cookie("remember_token")
    assert "email" in auths[0][1]

    assert is_authenticated(clients, get_message)

    logout(clients)
    assert not is_authenticated(clients, get_message)

    # login via SMS
    sms_sender = SmsSenderFactory.createSender("test")
    set_phone(app)
    response = clients.post(
        "/us-signin/send-code",
        data=dict(identity="matt@lp.com", chosen_method="sms"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Sign In" in response.data

    code = sms_sender.messages[0].split()[-1].strip(".")
    response = clients.post(
        "/us-signin",
        data=dict(identity="matt@lp.com", passcode=code, remember=True),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert clients.get_cookie("remember_token")
    assert "sms" in auths[1][1]

    assert is_authenticated(clients, get_message)

    logout(clients)
    assert not clients.get_cookie("remember_token")


def test_simple_signin_json(app, client_nc, get_message):
    set_email(app)
    auths = []

    @user_authenticated.connect_via(app)
    def authned(myapp, user, **extra_args):
        auths.append((user.email, extra_args["authn_via"]))

    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    with capture_flashes() as flashes:
        response = client_nc.get("/us-signin", headers=headers)
        jresponse = response.json["response"]
        assert (
            jresponse["available_methods"] == app.config["SECURITY_US_ENABLED_METHODS"]
        )
        assert jresponse["identity_attributes"] == get_identity_attributes(app=app)
        assert set(jresponse["code_methods"]) == {"email", "sms"}

        with capture_send_code_requests() as requests:
            response = client_nc.post(
                "/us-signin/send-code",
                json=dict(identity="matt@lp.com", chosen_method="email"),
                headers=headers,
                follow_redirects=True,
            )
            assert response.status_code == 200
            assert "csrf_token" in response.json["response"]
            assert "user" not in response.json["response"]
        assert len(requests) == 1
        assert len(app.mail.outbox) == 1

        # try bad code
        response = client_nc.post(
            "/us-signin",
            json=dict(identity="matt@lp.com", passcode="blahblah"),
            headers=headers,
            follow_redirects=True,
        )
        assert response.status_code == 400
        assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
            "INVALID_PASSWORD_CODE"
        )

        # Login successfully with code
        response = client_nc.post(
            "/us-signin?include_auth_token",
            json=dict(identity="matt@lp.com", passcode=requests[0]["token"]),
            headers=headers,
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert "authentication_token" in response.json["response"]["user"]
        assert "email" in auths[0][1]

        logout(client_nc)
        assert not is_authenticated(client_nc, get_message)

        # login via SMS
        sms_sender = SmsSenderFactory.createSender("test")
        set_phone(app)
        response = client_nc.post(
            "/us-signin/send-code",
            json=dict(identity="matt@lp.com", chosen_method="sms"),
            headers=headers,
            follow_redirects=True,
        )
        assert response.status_code == 200

        code = sms_sender.messages[0].split()[-1].strip(".")
        response = client_nc.post(
            "/us-signin?include_auth_token",
            json=dict(identity="matt@lp.com", passcode=code),
            headers=headers,
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert "authentication_token" in response.json["response"]["user"]
    assert len(flashes) == 0


@pytest.mark.changeable()
def test_signin_pwd_json(app, client, get_message):
    # Make sure us-signin accepts a normalized and original password.
    authenticate(client)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    data = dict(
        password="password",
        new_password="new strong password\N{ROMAN NUMERAL ONE}",
        new_password_confirm="new strong password\N{ROMAN NUMERAL ONE}",
    )
    response = client.post(
        "/change",
        json=data,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    logout(client)

    response = client.post(
        "/us-signin",
        json=dict(
            identity="matt@lp.com", passcode="new strong password\N{ROMAN NUMERAL ONE}"
        ),
        headers=headers,
        follow_redirects=False,
    )
    assert response.status_code == 200
    logout(client)

    response = client.post(
        "/us-signin",
        json=dict(
            identity="matt@lp.com",
            passcode="new strong password\N{LATIN CAPITAL LETTER I}",
        ),
        headers=headers,
        follow_redirects=False,
    )
    assert response.status_code == 200


@pytest.mark.registerable()
@pytest.mark.settings(password_required=False)
def test_us_passwordless(app, client, get_message):
    # Check passwordless.
    # Check contents of email template - this uses a test template
    # in order to check all context vars since the default template
    # doesn't have all of them.
    response = client.post(
        "/register", data=dict(email="nopasswd-dude@lp.com"), follow_redirects=True
    )
    logout(client)
    with capture_send_code_requests() as requests:
        response = client.post(
            "/us-signin/send-code",
            data=dict(identity="nopasswd-dude@lp.com", chosen_method="email"),
            follow_redirects=True,
        )
        outbox = app.mail.outbox
        # 2 emails - first from registration.
        assert len(outbox) == 2
        matcher = re.findall(r"\w+:.*", outbox[1].body, re.IGNORECASE)
        # should be 5 - link, email, token, config item, username
        assert matcher[1].split(":")[1] == "nopasswd-dude@lp.com"
        token = matcher[2].split(":")[1]
        assert token == requests[0]["token"]  # deprecated
        assert token == requests[0]["login_token"]
        assert matcher[3].split(":")[1] == "True"  # register_blueprint
        assert matcher[4].split(":")[1] == "nopasswd-dude@lp.com"

        # check link
        link = matcher[0].split(":", 1)[1]
        response = client.get(link, follow_redirects=True)
        assert get_message("PASSWORDLESS_LOGIN_SUCCESSFUL") in response.data

    # check us-setup has 'email' but not password
    response = client.get("/us-setup", json={})
    assert response.json["response"]["active_methods"] == ["email"]


@pytest.mark.registerable()
@pytest.mark.confirmable()
@pytest.mark.settings(password_required=False)
def test_us_passwordless_confirm(app, client, get_message):
    # Check passwordless with confirmation required.
    response = client.post(
        "/register", data=dict(email="nopasswd-dude@lp.com"), follow_redirects=True
    )
    # Try logging in - should get confirmation required.
    response = client.post(
        "/us-signin/send-code",
        data=dict(identity="nopasswd-dude@lp.com", chosen_method="email"),
        follow_redirects=True,
    )
    assert get_message("CONFIRMATION_REQUIRED") in response.data
    # grab welcome email which has confirmation link (test version of welcome.txt)
    outbox = app.mail.outbox
    matcher = re.findall(r"\w+:.*", outbox[0].body, re.IGNORECASE)
    link = matcher[0].split(":", 1)[1]
    response = client.get(link, follow_redirects=True)
    assert get_message("EMAIL_CONFIRMED") in response.data
    logout(client)

    # should be able to authenticate now.
    response = client.post(
        "/us-signin/send-code",
        data=dict(identity="nopasswd-dude@lp.com", chosen_method="email"),
        follow_redirects=True,
    )
    outbox = app.mail.outbox
    # 2 emails - first from registration.
    assert len(outbox) == 2
    matcher = re.findall(r"\w+:.*", outbox[1].body, re.IGNORECASE)
    # authenticate with link
    link = matcher[0].split(":", 1)[1]
    response = client.get(link, follow_redirects=True)
    assert get_message("PASSWORDLESS_LOGIN_SUCCESSFUL") in response.data


@pytest.mark.registerable()
@pytest.mark.confirmable()
@pytest.mark.settings(password_required=False)
def test_us_passwordless_confirm_json(app, client, get_message):
    # Check passwordless with confirmation required.
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = client.post("/register", json=dict(email="nopasswd-dude@lp.com"))
    # Try logging in - should get confirmation required.
    response = client.post(
        "/us-signin/send-code",
        json=dict(identity="nopasswd-dude@lp.com", chosen_method="email"),
    )
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "CONFIRMATION_REQUIRED"
    )

    # grab welcome email which has confirmation link (test version of welcome.txt)
    outbox = app.mail.outbox
    matcher = re.findall(r"\w+:.*", outbox[0].body, re.IGNORECASE)
    link = matcher[0].split(":", 1)[1]
    response = client.get(link, headers=headers, follow_redirects=False)
    assert response.location == "/login"

    # should be able to authenticate now.
    response = client.post(
        "/us-signin/send-code",
        json=dict(identity="nopasswd-dude@lp.com", chosen_method="email"),
    )
    outbox = app.mail.outbox
    # 2 emails - first from registration.
    assert len(outbox) == 2
    matcher = re.findall(r"\w+:.*", outbox[1].body, re.IGNORECASE)
    # authenticate with link
    link = matcher[0].split(":", 1)[1]
    response = client.get(link, headers=headers, follow_redirects=True)
    assert get_message("PASSWORDLESS_LOGIN_SUCCESSFUL") in response.data


def test_admin_setup_user_reset(app, client_nc, get_message):
    # Test that we can setup SMS using datastore admin method, and that
    # the datastore admin reset (reset_user_access) disables it.
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    sms_sender = SmsSenderFactory.createSender("test")
    set_phone(app)
    response = client_nc.post(
        "/us-signin/send-code",
        json=dict(identity="matt@lp.com", chosen_method="sms"),
        headers=headers,
        follow_redirects=True,
    )
    assert response.status_code == 200

    assert len(sms_sender.messages) == 1
    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client_nc.post(
        "/us-signin?include_auth_token",
        json=dict(identity="matt@lp.com", passcode=code),
        headers=headers,
        follow_redirects=True,
    )
    assert response.status_code == 200

    # logout, reset access
    logout(client_nc)
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        app.security.datastore.reset_user_access(user)
        app.security.datastore.commit()

    response = client_nc.post(
        "/us-signin/send-code",
        json=dict(identity="matt@lp.com", chosen_method="sms"),
        headers=headers,
        follow_redirects=True,
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "US_METHOD_NOT_AVAILABLE"
    )
    # Nothing should have been sent.
    assert len(sms_sender.messages) == 1


def test_admin_setup_reset(app, client_nc, get_message):
    # Test that we can setup SMS using datastore admin method, and that
    # the datastore admin reset (us_reset) disables it.
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    sms_sender = SmsSenderFactory.createSender("test")
    set_phone(app)
    response = client_nc.post(
        "/us-signin/send-code",
        json=dict(identity="matt@lp.com", chosen_method="sms"),
        headers=headers,
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert len(sms_sender.messages) == 1

    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        app.security.datastore.us_reset(user)
        app.security.datastore.commit()

    response = client_nc.post(
        "/us-signin/send-code",
        json=dict(identity="matt@lp.com", chosen_method="sms"),
        headers=headers,
        follow_redirects=True,
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "US_METHOD_NOT_AVAILABLE"
    )
    # Nothing should have been sent.
    assert len(sms_sender.messages) == 1


@pytest.mark.settings(post_login_view="/post_login")
def test_get_already_authenticated(client):
    response = authenticate(client, follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data
    response = client.get("/us-signin", follow_redirects=True)
    assert b"Post Login" in response.data


@pytest.mark.settings(post_login_view="/post_login")
def test_get_already_authenticated_next(client):
    response = authenticate(client, follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data
    # This should override post_login_view
    response = client.get("/us-signin?next=/page1", follow_redirects=True)
    assert b"Page 1" in response.data


@pytest.mark.settings(post_login_view="/post_login")
def test_post_already_authenticated(client, get_message):
    response = authenticate(client, follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/us-signin", data=data, follow_redirects=True)
    assert b"Post Login" in response.data
    response = client.post("/us-signin?next=/page1", data=data, follow_redirects=True)
    assert b"Page 1" in response.data

    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = client.post("/us-signin", json=data, headers=headers)
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "ANONYMOUS_USER_REQUIRED"
    )


@pytest.mark.settings(us_email_subject="Code For You")
def test_verify_link(app, client, get_message):
    set_email(app)
    auths = []

    @user_authenticated.connect_via(app)
    def authned(myapp, user, **extra_args):
        auths.append((user.email, extra_args["authn_via"]))

    response = client.post(
        "/us-signin/send-code",
        data=dict(identity="matt@lp.com", chosen_method="email"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Sign In" in response.data
    outbox = app.mail.outbox

    assert outbox[0].to == ["matt@lp.com"]
    assert outbox[0].from_email == "no-reply@localhost"
    assert outbox[0].subject == "Code For You"
    matcher = re.match(
        r".*(http://[^\s*]*).*", outbox[0].body, re.IGNORECASE | re.DOTALL
    )
    magic_link = matcher.group(1)

    # Try with no code
    response = client.get("us-verify-link?email=matt@lp.com", follow_redirects=False)
    assert "/us-signin" in response.location
    response = client.get("us-verify-link?email=matt@lp.com", follow_redirects=True)
    assert get_message("API_ERROR") in response.data

    # Try unknown user
    response = client.get(
        "us-verify-link?email=matt42@lp.com&code=12345", follow_redirects=True
    )
    assert get_message("USER_DOES_NOT_EXIST") in response.data

    # Try bad code
    response = client.get(
        "us-verify-link?email=matt@lp.com&code=12345", follow_redirects=True
    )
    assert get_message("INVALID_CODE") in response.data

    # Try actual link
    response = client.get(magic_link, follow_redirects=True)
    assert get_message("PASSWORDLESS_LOGIN_SUCCESSFUL") in response.data
    assert "email" in auths[0][1]

    # verify logged in
    assert is_authenticated(client, get_message)


@pytest.mark.settings(
    redirect_host="localhost:8081",
    redirect_behavior="spa",
    login_error_view="/login-error",
    post_login_view="/post-login",
)
def test_verify_link_spa(app, client, get_message):
    # N.B. we use client here since this only works/ is supported if using
    # sessions.
    set_email(app)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = client.post(
        "/us-signin/send-code",
        json=dict(identity="matt@lp.com", chosen_method="email"),
        headers=headers,
    )
    assert response.status_code == 200
    outbox = app.mail.outbox

    matcher = re.match(
        r".*(http://[^\s*]*).*", outbox[0].body, re.IGNORECASE | re.DOTALL
    )
    magic_link = matcher.group(1)

    # Try with no code
    response = client.get("us-verify-link?email=matt@lp.com", follow_redirects=False)
    assert response.status_code == 302
    split = urlsplit(response.headers["Location"])
    assert "localhost:8081" == split.netloc
    assert "/login-error" == split.path
    qparams = dict(parse_qsl(split.query))
    assert get_message("API_ERROR") == qparams["error"].encode("utf-8")

    # Try unknown user
    response = client.get(
        "us-verify-link?email=matt42@lp.com&code=12345", follow_redirects=False
    )
    assert response.status_code == 302
    split = urlsplit(response.headers["Location"])
    assert "localhost:8081" == split.netloc
    assert "/login-error" == split.path
    qparams = dict(parse_qsl(split.query))
    assert get_message("USER_DOES_NOT_EXIST") == qparams["error"].encode("utf-8")

    # Try bad code
    response = client.get(
        "us-verify-link?email=matt@lp.com&code=12345", follow_redirects=False
    )
    assert response.status_code == 302
    split = urlsplit(response.headers["Location"])
    assert "localhost:8081" == split.netloc
    assert "/login-error" == split.path
    qparams = dict(parse_qsl(split.query))
    assert get_message("INVALID_CODE") == qparams["error"].encode("utf-8")

    # Try actual link
    response = client.get(magic_link, follow_redirects=False)
    assert response.status_code == 302
    split = urlsplit(response.headers["Location"])
    assert "localhost:8081" == split.netloc
    assert "/post-login" == split.path
    qparams = dict(parse_qsl(split.query))
    assert qparams["email"] == "matt@lp.com"

    assert is_authenticated(client, get_message)


def test_setup(app, client, get_message):
    set_email(app)
    us_authenticate(client)
    response = client.get("us-setup")
    # Email should be in delete options since we just set that up.
    assert all(
        i in response.data
        for i in [b"delete_method-0", b"chosen_method-0", b"chosen_method-1"]
    )

    # test not supplying anything to do
    response = client.post("us-setup", data=dict(phone="6505551212"))
    assert get_message("API_ERROR") in response.data

    # test missing phone
    response = client.post("us-setup", data=dict(chosen_method="sms", phone=""))
    assert response.status_code == 200
    assert get_message("PHONE_INVALID") in response.data

    # test invalid phone
    response = client.post("us-setup", data=dict(chosen_method="sms", phone="555-1212"))
    assert response.status_code == 200
    assert get_message("PHONE_INVALID") in response.data
    assert b"Enter code here to complete setup" not in response.data

    sms_sender = SmsSenderFactory.createSender("test")
    response = client.post(
        "us-setup", data=dict(chosen_method="sms", phone="650-555-1212")
    )
    assert response.status_code == 200
    assert b"Submit Code" in response.data
    assert b"Enter code here to complete setup" in response.data

    verify_url = get_form_action(response, 1)

    # Try invalid code
    response = client.post(verify_url, data=dict(passcode=12345), follow_redirects=True)
    assert get_message("INVALID_PASSWORD_CODE") in response.data

    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post(verify_url, data=dict(passcode=code), follow_redirects=True)
    assert response.status_code == 200
    assert get_message("US_SETUP_SUCCESSFUL") in response.data


def test_setup_email(app, client, get_message):
    # setup with email - make sure magic link isn't sent and code is.
    # N.B. this is using the test us_instructions template
    set_email(app)
    us_authenticate(client)
    response = client.post("us-setup", data=dict(chosen_method="email"))
    assert response.status_code == 200
    assert b"Enter code here to complete setup" in response.data
    outbox = app.mail.outbox

    verify_url = get_form_action(response, 1)

    # verify no magic link - us_authenticate received first email - we want the second
    matcher = re.findall(r"\w+:.*", outbox[1].body, re.IGNORECASE)
    # should be 4 - link, email, token, config item
    assert matcher[0].split(":")[1] == "None"
    assert matcher[1].split(":")[1] == "matt@lp.com"

    code = matcher[2].split(":")[1]
    response = client.post(verify_url, data=dict(passcode=code), follow_redirects=True)
    assert response.status_code == 200
    assert get_message("US_SETUP_SUCCESSFUL") in response.data


@pytest.mark.settings(
    us_enabled_methods=["email", "sms"],
    user_identity_attributes=UIA_EMAIL_PHONE,
    freshness=timedelta(hours=-1),
)
def test_setup_json(app, client_nc, get_message):
    # This shows that by setting freshness to negative doesn't require session.
    @us_profile_changed.connect_via(app)
    def pc(sender, user, methods, delete, **kwargs):
        assert not delete
        assert methods == ["sms"]
        assert user.us_phone_number == "+16505551212"

    set_email(app)
    token = us_authenticate(client_nc)
    headers = {
        "Authentication-Token": token,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    response = client_nc.get("/us-setup", headers=headers)
    assert response.status_code == 200
    assert response.json["response"]["available_methods"] == ["email", "sms"]
    assert set(response.json["response"]["setup_methods"]) == {"email", "sms"}
    assert set(response.json["response"]["active_methods"]) == {"email", "password"}

    sms_sender = SmsSenderFactory.createSender("test")
    response = client_nc.post(
        "us-setup",
        json=dict(chosen_method="sms", phone="650-555-1212"),
        headers=headers,
    )
    assert response.status_code == 200
    state = response.json["response"]["state"]
    assert state

    # send invalid code
    response = client_nc.post(
        "/us-setup/" + state, json=dict(passcode=12344), headers=headers
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "INVALID_PASSWORD_CODE"
    )
    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client_nc.post(
        "/us-setup/" + state, json=dict(passcode=code), headers=headers
    )
    assert response.status_code == 200
    assert response.json["response"]["chosen_method"] == "sms"
    assert response.json["response"]["phone"] == "+16505551212"

    # Verify sms in list of 'active' methods
    response = client_nc.get("/us-setup", headers=headers)
    assert response.status_code == 200
    assert set(response.json["response"]["active_methods"]) == {
        "email",
        "sms",
        "password",
    }

    # now login with phone - send in different format than we set up with.
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    sms_sender = SmsSenderFactory.createSender("test")
    response = client_nc.post(
        "/us-signin/send-code",
        json=dict(identity="6505551212", chosen_method="sms"),
        headers=headers,
    )
    assert response.status_code == 200
    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client_nc.post(
        "/us-signin?include_auth_token",
        json=dict(identity="matt@lp.com", passcode=code),
        headers=headers,
    )
    assert response.status_code == 200
    assert "authentication_token" in response.json["response"]["user"]


@pytest.mark.settings(
    us_enabled_methods=["email", "sms"],
    user_identity_attributes=UIA_EMAIL_PHONE,
)
def test_setup_json_no_session(app, client_nc, get_message):
    # Test that with normal config freshness is required so must have session.
    set_email(app)
    token = us_authenticate(client_nc)
    headers = {
        "Authentication-Token": token,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    response = client_nc.get("/us-setup", headers=headers)
    assert response.status_code == 401
    assert response.json["response"]["reauth_required"]
    assert "WWW-Authenticate" not in response.headers


@pytest.mark.settings(api_enabled_methods=["basic"])
def test_setup_basic(app, client, get_message):
    # If using Basic Auth - always fresh so should be able to setup (not sure the
    # use case but...)
    headers = {
        "Authorization": "Basic %s"
        % base64.b64encode(b"matt@lp.com:password").decode("utf-8")
    }
    response = client.get("/us-setup", headers=headers)
    assert response.status_code == 200
    assert b"Setup Unified Sign In" in response.data


def test_setup_bad_token(app, client, get_message):
    set_email(app)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    us_authenticate(client)

    # bogus state
    response = client.post(
        "/us-setup/not a token", json=dict(passcode=12345), headers=headers
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "API_ERROR"
    )

    # same w/o json
    response = client.post(
        "/us-setup/not a token", data=dict(passcode=12345), follow_redirects=True
    )
    assert get_message("API_ERROR") in response.data


@pytest.mark.settings(us_setup_within="2 seconds")
def test_setup_timeout(app, client, get_message):
    # Test setup timeout
    set_email(app)
    us_authenticate(client)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    sms_sender = SmsSenderFactory.createSender("test")
    app.security.us_setup_serializer = FakeSerializer(2.0)
    response = client.post(
        "us-setup",
        json=dict(chosen_method="sms", phone="650-555-1212"),
        headers=headers,
    )
    assert response.status_code == 200
    state = response.json["response"]["state"]

    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post(
        "/us-setup/" + state, json=dict(passcode=code), headers=headers
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "US_SETUP_EXPIRED", within=app.config["SECURITY_US_SETUP_WITHIN"]
    )


@pytest.mark.settings(
    us_enabled_methods=["email", "sms"],
    user_identity_attributes=UIA_EMAIL_PHONE,
)
def test_unique_phone(app, client, get_message):
    # Test that us_phone_number is properly validated to be unique
    set_email(app, email="matt@lp.com")
    us_authenticate(client, identity="matt@lp.com")

    sms_sender = SmsSenderFactory.createSender("test")
    response = client.post(
        "us-setup",
        json=dict(chosen_method="sms", phone="650-555-1212"),
    )
    assert response.status_code == 200
    state = response.json["response"]["state"]
    assert state
    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post("/us-setup/" + state, json=dict(passcode=code))
    assert response.status_code == 200

    logout(client)

    set_email(app, email="joe@lp.com")
    us_authenticate(client, identity="joe@lp.com")
    response = client.post(
        "us-setup",
        json=dict(chosen_method="sms", phone="650-555-1212"),
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode() == get_message(
        "IDENTITY_ALREADY_ASSOCIATED", attr="us_phone_number", value="+16505551212"
    )


@pytest.mark.settings(freshness=timedelta(minutes=0))
def test_verify(app, client, get_message):
    # Test setup when re-authenticate required
    # With  freshness set to 0 - the first call should require reauth (by
    # redirecting); but the second should work due to grace period.
    set_email(app)
    us_authenticate(client)
    response = client.get("us-setup", follow_redirects=False)
    verify_url = response.location
    assert "/us-verify?next=http://localhost/us-setup" in verify_url
    logout(client)
    us_authenticate(client)

    response = client.get("us-setup", follow_redirects=True)
    form_response = response.data.decode("utf-8")
    assert "Please Reauthenticate" in form_response
    send_code_url = get_form_action(response, 1)

    # Send unknown method
    response = client.post(
        send_code_url,
        data=dict(identity="matt@lp.com", chosen_method="sms2"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Not a valid choice" in response.data

    # Verify using SMS
    sms_sender = SmsSenderFactory.createSender("test")
    set_phone(app)
    response = client.post(
        send_code_url,
        data=dict(identity="matt@lp.com", chosen_method="sms"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Code has been sent" in response.data

    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post(verify_url, data=dict(passcode=code), follow_redirects=False)
    assert response.location == "http://localhost/us-setup"


def test_verify_json(app, client, get_message):
    # Test setup when re-authenticate required
    # N.B. with freshness=0 we never set a grace period and should never be able to
    # get to /us-setup
    set_email(app)
    us_authenticate(client)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    app.config["SECURITY_FRESHNESS"] = timedelta(minutes=0)
    response = client.get("us-setup", headers=headers)
    assert response.status_code == 401
    assert response.json["response"]["reauth_required"]

    # figure out which methods are usable
    response = client.get("us-verify", headers=headers)
    assert response.json["response"]["available_methods"] == [
        "password",
        "email",
        "authenticator",
        "sms",
    ]
    # code_methods should just contain active/setup methods.
    assert set(response.json["response"]["code_methods"]) == {
        "email",
    }

    response = client.post(
        "us-verify/send-code",
        json=dict(chosen_method="orb"),
        headers=headers,
    )
    assert response.status_code == 400

    # Verify using SMS
    sms_sender = SmsSenderFactory.createSender("test")
    set_phone(app)
    response = client.post(
        "us-verify/send-code",
        json=dict(chosen_method="sms"),
        headers=headers,
    )
    assert response.status_code == 200

    # Try bad code
    response = client.post("us-verify", json=dict(passcode=42), headers=headers)
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "INVALID_PASSWORD_CODE"
    )
    assert response.json["response"]["field_errors"]["passcode"][0].encode(
        "utf-8"
    ) == get_message("INVALID_PASSWORD_CODE")

    response = client.post("us-verify", json=dict(passcode=None), headers=headers)
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "INVALID_PASSWORD_CODE"
    )

    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post("us-verify", json=dict(passcode=code), headers=headers)
    assert response.status_code == 200

    app.config["SECURITY_FRESHNESS"] = timedelta(minutes=60)
    response = client.get("us-setup", headers=headers)
    assert response.status_code == 200


@pytest.mark.settings(freshness=timedelta(minutes=-1))
def test_setup_nofresh(app, client, get_message):
    set_email(app)
    us_authenticate(client)
    response = client.get("us-setup", follow_redirects=False)
    assert response.status_code == 200

    response = client.get("us-verify")
    assert response.status_code == 404


@pytest.mark.settings(us_enabled_methods=["sms"])
def test_invalid_method(app, client, get_message):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    response = client.get("/us-signin", headers=headers)
    assert response.json["response"]["available_methods"] == ["sms"]

    # verify json error
    response = client.post(
        "/us-signin/send-code",
        json=dict(identity="matt@lp.com", chosen_method="email"),
        headers=headers,
        follow_redirects=True,
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "US_METHOD_NOT_AVAILABLE"
    )

    # verify form error
    response = client.post(
        "/us-signin/send-code",
        data=dict(identity="matt@lp.com", chosen_method="email"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert get_message("US_METHOD_NOT_AVAILABLE") in response.data


@pytest.mark.settings(us_enabled_methods=["sms", "email"])
def test_invalid_method_setup(app, client, get_message):
    set_email(app)
    us_authenticate(client)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    response = client.get("/us-setup", headers=headers)
    assert response.json["response"]["available_methods"] == ["sms", "email"]

    # verify json error
    response = client.post(
        "/us-setup",
        json=dict(email="matt@lp.com", chosen_method="authenticator"),
        headers=headers,
        follow_redirects=True,
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "US_METHOD_NOT_AVAILABLE"
    )

    response = client.post(
        "/us-setup",
        data=dict(email="matt@lp.com", chosen_method="authenticators"),
        follow_redirects=True,
    )
    assert get_message("US_METHOD_NOT_AVAILABLE") in response.data


def test_setup_new_totp(app, client, get_message):
    # us-setup should generate a new totp secret for each setup
    # Verify existing codes no longer work
    set_email(app)
    us_authenticate(client)

    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    # Start by generating a good code - this will generate a new totp
    sms_sender = SmsSenderFactory.createSender("test")
    response = client.post(
        "us-setup",
        json=dict(chosen_method="sms", phone="650-555-1212"),
        headers=headers,
    )
    assert response.status_code == 200
    assert "authr_key" not in response.json["response"]
    code = sms_sender.messages[0].split()[-1].strip(".")

    # Now start setup again - it should generate a new totp - so the previous 'code'
    # should no longer work
    sms_sender2 = SmsSenderFactory.createSender("test")
    response = client.post(
        "us-setup",
        json=dict(chosen_method="sms", phone="650-555-1212"),
        headers=headers,
    )
    assert response.status_code == 200
    state = response.json["response"]["state"]
    # Use old code
    response = client.post(
        "/us-setup/" + state, json=dict(passcode=code), headers=headers
    )
    assert response.status_code == 400

    # Use new code
    code = sms_sender2.messages[0].split()[-1].strip(".")
    response = client.post(
        "/us-setup/" + state, json=dict(passcode=code), headers=headers
    )
    assert response.status_code == 200
    assert response.json["response"]["chosen_method"] == "sms"
    assert response.json["response"]["phone"] == "+16505551212"


def test_qrcode(app, client, get_message):
    # Test forms based authenticator setup - can't really parse QRcode - but can use
    # the key sent as part of the response.
    set_email(app, email="gal@lp.com")
    us_authenticate(client, identity="gal@lp.com")
    response = client.post("us-setup", data=dict(chosen_method="authenticator"))
    assert response.status_code == 200
    # verify png QRcode is present
    assert b"data:image/svg+xml;base64," in response.data

    # parse out key
    rd = response.data.decode("utf-8")
    matcher = re.match(r".*((?:\S{4}-){7}\S{4}).*", rd, re.DOTALL)
    totp_secret = matcher.group(1)

    # Generate token from passed totp_secret and confirm setup
    totp = TOTP(totp_secret)
    code = totp.generate().token

    # get verify link e.g. /us-setup/{state}
    verify_url = get_form_action(response, 1)

    response = client.post(verify_url, data=dict(passcode=code), follow_redirects=True)
    assert response.status_code == 200
    assert get_message("US_SETUP_SUCCESSFUL") in response.data


def test_next(app, client, get_message):
    set_email(app)
    with capture_send_code_requests() as requests:
        response = client.post(
            "/us-signin/send-code",
            data=dict(identity="matt@lp.com", chosen_method="email"),
            follow_redirects=True,
        )
        assert response.status_code == 200

    response = client.post(
        "/us-signin?next=/post_login",
        data=dict(identity="matt@lp.com", passcode=requests[0]["token"]),
        follow_redirects=False,
    )
    assert "/post_login" in response.location

    logout(client)
    response = client.post(
        "/us-signin",
        data=dict(
            identity="matt@lp.com", passcode=requests[0]["token"], next="/post_login"
        ),
        follow_redirects=False,
    )

    assert "/post_login" in response.location


@pytest.mark.registerable()
@pytest.mark.confirmable()
@pytest.mark.settings(requires_confirmation_error_view="/confirm")
def test_requires_confirmation_error_redirect(app, client):
    data = dict(
        email="jyl@lp.com", password="password", password_confirm="password", next=""
    )
    response = client.post("/register", data=data, follow_redirects=True)
    set_email(app, email="jyl@lp.com")

    response = client.post(
        "/us-signin/send-code",
        data=dict(identity="jyl@lp.com", chosen_method="email"),
        follow_redirects=False,
    )
    assert "/confirm" in response.location

    response = client.post(
        "/us-signin",
        data=dict(identity="jyl@lp.com", passcode="password"),
        follow_redirects=False,
    )
    assert "/confirm" in response.location


@pytest.mark.registerable()
@pytest.mark.confirmable()
def test_confirmable(app, client, get_message):
    # Verify can't log in if need confirmation.
    data = dict(
        email="dude@lp.com", password="password", password_confirm="password", next=""
    )
    response = client.post("/register", data=data, follow_redirects=True)
    assert response.status_code == 200
    set_email(app, email="dude@lp.com")

    response = client.post(
        "/us-signin/send-code",
        data=dict(identity="dude@lp.com", chosen_method="email"),
        follow_redirects=True,
    )
    assert response.status_code == 200

    assert get_message("CONFIRMATION_REQUIRED") in response.data

    # Verify not authenticated
    assert not is_authenticated(client, get_message)


@pytest.mark.registerable()
@pytest.mark.recoverable()
@pytest.mark.settings(password_required=False)
def test_can_add_password(app, client, get_message):
    # Test that if register w/o a password, can use 'recover password' to assign one
    data = dict(email="trp@lp.com", password="")
    response = client.post("/register", data=data, follow_redirects=True)
    assert b"Welcome trp@lp.com" in response.data
    logout(client)

    with capture_reset_password_requests() as requests:
        client.post("/reset", data=dict(email="trp@lp.com"), follow_redirects=True)
    token = requests[0]["token"]

    response = client.post(
        "/reset/" + token,
        data={"password": "awesome sunset", "password_confirm": "awesome sunset"},
        follow_redirects=True,
    )

    assert get_message("PASSWORD_RESET_NO_LOGIN") in response.data

    # authenticate with new password using standard/old login endpoint.
    response = authenticate(
        client, "trp@lp.com", "awesome sunset", follow_redirects=True
    )
    assert b"Welcome trp@lp.com" in response.data

    logout(client)
    # authenticate with password and us-signin endpoint
    response = client.post(
        "/us-signin",
        data=dict(identity="trp@lp.com", passcode="awesome sunset"),
        follow_redirects=True,
    )
    assert b"Welcome trp@lp.com" in response.data


@pytest.mark.registerable()
@pytest.mark.changeable()
@pytest.mark.settings(password_required=False)
def test_change_empty_password(app, client):
    # test that if register w/o a password - can 'change' it.
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    data = dict(email="trp@lp.com", password="")
    response = client.post("/register", data=data, follow_redirects=True)
    # should have been logged in since no confirmation

    # make sure requires a fresh authentication
    reset_fresh(client, app.config["SECURITY_FRESHNESS"])
    data = dict(
        password="",
        new_password="awesome sunset",
        new_password_confirm="awesome sunset",
    )

    response = client.post("/change", json=data)
    assert response.status_code == 401
    assert response.json["response"]["reauth_required"]

    client.post(
        "/us-verify/send-code",
        json=dict(identity="trp@lp.com", chosen_method="email"),
    )
    outbox = app.mail.outbox
    matcher = re.match(r".*Token:(\d+).*", outbox[1].body, re.IGNORECASE | re.DOTALL)
    code = matcher.group(1)
    response = client.post("/us-verify", json=dict(passcode=code))
    assert response.status_code == 200

    response = client.get("/change", headers=headers)
    assert not response.json["response"]["active_password"]
    response = client.get("/change")
    assert b"You do not" in response.data

    # now should be able to change
    response = client.post("/change", json=data)
    assert response.status_code == 200
    logout(client)

    response = client.post(
        "/login", json=dict(email="trp@lp.com", password="awesome sunset")
    )
    assert response.status_code == 200


@pytest.mark.registerable()
@pytest.mark.settings(password_required=False)
def test_empty_password(app, client, get_message):
    # test that if no password - can't log in with empty password
    data = dict(email="trp@lp.com", password="")
    response = client.post("/register", data=data, follow_redirects=True)
    logout(client)

    response = client.post("/us-signin", json=dict(identity="trp@lp.com", passcode=""))
    assert response.status_code == 400
    assert response.json["response"]["field_errors"]["passcode"][0].encode(
        "utf-8"
    ) == get_message("INVALID_PASSWORD_CODE")
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "INVALID_PASSWORD_CODE"
    )


@pytest.mark.settings(
    us_enabled_methods=["password"],
    user_identity_attributes=[
        {"email": {"mapper": uia_email_mapper}},
        {"username": {"mapper": lambda x: x}},
    ],
)
def test_regular_login(app, client, get_message):
    # If "password" in methods - then should be able to login with good-ol
    # login/password.
    # By having username - this also checks that we properly stop at the first
    # mapping.
    auths = []

    @user_authenticated.connect_via(app)
    def authned(myapp, user, **extra_args):
        auths.append((user.email, extra_args["authn_via"]))

    response = client.post(
        "/us-signin",
        data=dict(identity="matt@lp.com", passcode="password", remember=True),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert client.get_cookie("remember_token")
    assert "password" in auths[0][1]
    assert is_authenticated(client, get_message)


@pytest.mark.settings(
    us_enabled_methods=["sms"], user_identity_attributes=UIA_EMAIL_PHONE
)
def test_regular_login_disallowed(app, client, get_message):
    # If "password" not in methods - then should not be able to use password
    response = client.post(
        "/us-signin",
        data=dict(identity="matt@lp.com", passcode="password", remember=True),
        follow_redirects=True,
    )
    assert get_message("INVALID_PASSWORD_CODE") in response.data


@pytest.mark.two_factor()
@pytest.mark.settings(two_factor_required=True)
def test_tf(app, client, get_message):
    # Test basic two-factor - default for signing in with password.
    response = client.post(
        "/us-signin",
        data=dict(identity="matt@lp.com", passcode="password", remember=True),
        follow_redirects=True,
    )
    assert response.status_code == 200
    message = b"Two-factor authentication adds an extra layer of security"
    assert message in response.data
    assert b"Set up using SMS" in response.data

    sms_sender = SmsSenderFactory.createSender("test")
    data = dict(setup="sms", phone="+442083661177")
    response = client.post("/tf-setup", data=data, follow_redirects=True)
    assert b"To Which Phone Number Should We Send Code To" in response.data
    code = sms_sender.messages[0].split()[-1]

    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert get_message("TWO_FACTOR_LOGIN_SUCCESSFUL") in response.data


@pytest.mark.two_factor()
@pytest.mark.settings(two_factor_required=True)
def test_tf_link(app, client, get_message):
    # Verify two-factor required when using magic link
    set_email(app)
    response = client.post(
        "/us-signin/send-code",
        data=dict(identity="matt@lp.com", chosen_method="email"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Sign In" in response.data
    outbox = app.mail.outbox

    matcher = re.match(
        r".*(http://[^\s*]*).*", outbox[0].body, re.IGNORECASE | re.DOTALL
    )
    magic_link = matcher.group(1)
    response = client.get(magic_link, follow_redirects=True)
    assert get_message("PASSWORDLESS_LOGIN_SUCCESSFUL") not in response.data
    message = b"Two-factor authentication adds an extra layer of security"
    assert message in response.data


@pytest.mark.two_factor()
@pytest.mark.settings(
    two_factor_required=True,
    redirect_host="localhost:8081",
    redirect_behavior="spa",
    login_error_view="/login-error",
)
def test_tf_link_spa(app, client, get_message):
    # Verify two-factor required when using magic link and SPA
    # This currently isn't supported and should redirect to an error.
    set_email(app)
    response = client.post(
        "/us-signin/send-code",
        data=dict(identity="matt@lp.com", chosen_method="email"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Sign In" in response.data
    outbox = app.mail.outbox

    matcher = re.match(
        r".*(http://[^\s*]*).*", outbox[0].body, re.IGNORECASE | re.DOTALL
    )
    magic_link = matcher.group(1)
    response = client.get(magic_link, follow_redirects=False)
    split = urlsplit(response.location)
    assert "localhost:8081" == split.netloc
    assert "/login-error" == split.path
    qparams = dict(parse_qsl(split.query))
    assert qparams["tf_required"] == "1"
    assert qparams["email"] == "matt@lp.com"


@pytest.mark.two_factor()
@pytest.mark.settings(
    two_factor_required=True, user_identity_attributes=UIA_EMAIL_PHONE
)
def test_tf_not(app, client, get_message):
    # Test basic two-factor - when first factor doesn't require second (e.g. SMS)
    # 1. sign in and setup TFA
    client.post(
        "/us-signin",
        data=dict(identity="matt@lp.com", passcode="password", remember=True),
        follow_redirects=True,
    )

    sms_sender = SmsSenderFactory.createSender("test")
    data = dict(setup="sms", phone="+442083661177")
    client.post("/tf-setup", data=data, follow_redirects=True)
    code = sms_sender.messages[0].split()[-1]
    client.post("/tf-validate", data=dict(code=code), follow_redirects=True)

    # 2. setup unified sign in with SMS
    response = client.post(
        "us-setup", data=dict(chosen_method="sms", phone="650-555-1212")
    )
    verify_url = get_form_action(response, 1)
    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post(verify_url, data=dict(passcode=code), follow_redirects=True)
    assert response.status_code == 200
    assert get_message("US_SETUP_SUCCESSFUL") in response.data

    # 3. logout
    logout(client)

    # 4. sign in with SMS - should not require TFA
    client.post(
        "/us-signin/send-code",
        data=dict(identity="matt@lp.com", chosen_method="sms"),
        follow_redirects=True,
    )

    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post(
        "/us-signin",
        data=dict(identity="6505551212", passcode=code),
        follow_redirects=True,
    )
    assert response.status_code == 200
    # assert "sms" in auths[1][1]

    # Verify authenticated
    assert is_authenticated(client, get_message)


@pytest.mark.settings(sms_service="bad")
def test_bad_sender(app, client, get_message):
    # If SMS sender fails - make sure propagated
    # Test form, json, x signin, setup
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    set_phone(app)
    data = dict(identity="matt@lp.com", chosen_method="sms")
    response = client.post("/us-signin/send-code", data=data, follow_redirects=True)
    assert get_message("FAILED_TO_SEND_CODE") in response.data

    response = client.post("us-signin/send-code", json=data, headers=headers)
    assert response.status_code == 500
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "FAILED_TO_SEND_CODE"
    )

    # Now test setup
    set_email(app)
    us_authenticate(client)
    data = dict(chosen_method="sms", phone="650-555-1212")
    response = client.post("us-setup", data=data)
    assert get_message("FAILED_TO_SEND_CODE") in response.data

    response = client.post("us-setup", json=data, headers=headers)
    assert response.status_code == 500
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "FAILED_TO_SEND_CODE"
    )

    # Test us-verify
    data = dict(chosen_method="sms")
    response = client.post("/us-verify/send-code", data=data)
    assert get_message("FAILED_TO_SEND_CODE") in response.data
    response = client.post("us-verify/send-code", json=data)
    assert response.status_code == 500
    assert response.json["response"]["field_errors"]["chosen_method"][0].encode(
        "utf-8"
    ) == get_message("FAILED_TO_SEND_CODE")


@pytest.mark.registerable()
def test_replace_send_code(app, get_message):
    pytest.importorskip("sqlalchemy")

    from flask_sqlalchemy import SQLAlchemy
    from flask_security.models import fsqla_v2 as fsqla
    from flask_security import Security, us_send_security_token

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    db = SQLAlchemy(app)

    fsqla.FsModels.set_db_info(db)

    class Role(db.Model, fsqla.FsRoleMixin):
        pass

    class User(db.Model, fsqla.FsUserMixin):
        def us_send_security_token(self, method, **kwargs):
            assert method == "sms"
            us_send_security_token(self, method, **kwargs)

    with app.app_context():
        db.create_all()

    ds = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(app, datastore=ds)

    with app.app_context():
        client = app.test_client()

        # since we don't use client fixture - have to add user
        data = dict(email="trp@lp.com", password="password")
        response = client.post("/register", data=data, follow_redirects=True)
        assert b"Welcome trp@lp.com" in response.data
        logout(client)

        set_phone(app, email="trp@lp.com")
        data = dict(identity="trp@lp.com", chosen_method="sms")
        response = client.post("/us-signin/send-code", data=data, follow_redirects=True)
        assert b"Code has been sent" in response.data


@pytest.mark.settings(us_enabled_methods=["password"])
def test_only_passwd(app, client, get_message):
    authenticate(client)
    response = client.get("us-setup")
    assert b"No method" in response.data

    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = client.get("us-setup", headers=headers)
    assert response.json["response"]["available_methods"] == ["password"]
    assert not response.json["response"]["setup_methods"]


@pytest.mark.settings(us_enabled_methods=["password", "authenticator"])
def test_passwd_and_authenticator(app, client, get_message):
    authenticate(client)
    response = client.get("us-setup")
    assert b"authenticator app" in response.data

    # Check that we get QRcode URL and no 'code sent'
    response = client.post("us-setup", data=dict(chosen_method="authenticator"))
    assert response.status_code == 200
    assert b"Code has been sent" not in response.data
    assert b"Open an authenticator app" in response.data
    # verify png QRcode is present
    assert b"data:image/svg+xml;base64," in response.data

    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = client.get("us-setup", headers=headers)
    assert response.json["response"]["available_methods"] == [
        "password",
        "authenticator",
    ]
    assert response.json["response"]["setup_methods"] == ["authenticator"]


def test_totp_generation(app, client, get_message):
    # Test that we generate a new totp on each setup of a different method
    # and that on failure to validate, the secret is NOT changed in the DB
    # and on successful validation, it is.
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    authenticate(client, email="dave@lp.com")
    with app.app_context():
        user = app.security.datastore.find_user(email="dave@lp.com")
        ts = app.security.datastore.us_get_totp_secrets(user)
        assert "authenticator" not in ts

    response = client.post(
        "us-setup", json=dict(chosen_method="authenticator"), headers=headers
    )
    assert response.status_code == 200
    assert response.json["response"]["authr_issuer"] == "service_name"
    assert response.json["response"]["authr_username"] == "dave@lp.com"
    assert "authr_key" in response.json["response"]

    state = response.json["response"]["state"]

    # Generate token from passed totp_secret and confirm setup
    totp_key = response.json["response"]["authr_key"]
    totp = TOTP(totp_key)
    code = totp.generate().token

    response = client.post(
        "/us-setup/" + state, json=dict(passcode=code), headers=headers
    )
    assert response.status_code == 200
    assert response.json["response"]["chosen_method"] == "authenticator"

    # success - totp_secret in DB should have been saved
    with app.app_context():
        user = app.security.datastore.find_user(email="dave@lp.com")
        ts = app.security.datastore.us_get_totp_secrets(user)
        assert (
            app.security._totp_factory.get_totp_pretty_key(ts["authenticator"])
            == totp_key
        )

    # Now setup SMS and verify that authenticator totp hasn't changed
    sms_sender = SmsSenderFactory.createSender("test")
    response = client.post(
        "us-setup",
        json=dict(chosen_method="sms", phone="650-555-1212"),
        headers=headers,
    )
    assert response.status_code == 200
    code = sms_sender.messages[0].split()[-1].strip(".")
    state = response.json["response"]["state"]
    response = client.post(
        "/us-setup/" + state, json=dict(passcode=code), headers=headers
    )
    assert response.status_code == 200
    assert response.json["response"]["chosen_method"] == "sms"
    assert response.json["response"]["phone"] == "+16505551212"

    # make sure authenticator totp hasn't changed.
    with app.app_context():
        user = app.security.datastore.find_user(email="dave@lp.com")
        ts = app.security.datastore.us_get_totp_secrets(user)
        assert (
            app.security._totp_factory.get_totp_pretty_key(ts["authenticator"])
            == totp_key
        )

    # Ok - setup again - but send invalid code - check totp in DB didn't change.
    response = client.post(
        "us-setup", json=dict(chosen_method="authenticator"), headers=headers
    )
    assert response.status_code == 200
    state = response.json["response"]["state"]
    totp_key = response.json["response"]["authr_key"]

    # validate with wrong code
    response = client.post(
        "/us-setup/" + state, json=dict(passcode=123345), headers=headers
    )
    assert response.status_code == 400

    # Make sure totp_secret in DB didn't change
    with app.app_context():
        user = app.security.datastore.find_user(email="dave@lp.com")
        ts = app.security.datastore.us_get_totp_secrets(user)
        assert (
            app.security._totp_factory.get_totp_pretty_key(ts["authenticator"])
            != totp_key
        )


@pytest.mark.two_factor()
@pytest.mark.settings(
    two_factor_required=True,
    user_identity_attributes=UIA_EMAIL_PHONE,
    two_factor_always_validate=False,
)
def test_us_tf_validity(app, client, get_message):
    us_tf_authenticate(app, client, remember=True)
    assert client.get_cookie("tf_validity")
    logout(client)
    # logout does NOT remove this cookie
    assert client.get_cookie("tf_validity")

    # This time shouldn't require code
    data = dict(identity="gal@lp.com", passcode="password")
    response = client.post("/us-signin", json=data)
    assert response.json["meta"]["code"] == 200
    assert is_authenticated(client, get_message)
    logout(client)

    data = dict(identity="gal2@lp.com", passcode="password")
    response = client.post("/us-signin", data=data, follow_redirects=True)
    assert b"Please enter your authentication code" in response.data

    response = client.post(
        "/us-signin",
        json=data,
        follow_redirects=True,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    assert response.json["response"]["tf_primary_method"] == "authenticator"
    assert response.json["response"]["tf_required"]
    assert response.json["response"]["tf_state"] == "ready"


@pytest.mark.webauthn()
@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_us_verify_wan(app, client, get_message):
    # test get correct options when requiring a reauthentication and have wan keys
    # setup.
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    reg_2_keys(client)

    reset_fresh(client, app.config["SECURITY_FRESHNESS"])
    response = client.get("us-setup", headers=headers)
    assert response.status_code == 401
    assert response.json["response"]["reauth_required"]
    assert response.json["response"]["has_webauthn_verify_credential"]

    # the us-verify form should have the webauthn verify form attached
    response = client.get("us-verify")
    assert b'action="/wan-verify"' in response.data

    app.config["SECURITY_WAN_ALLOW_AS_VERIFY"] = None
    response = client.get("us-setup", headers=headers)
    assert response.status_code == 401
    assert response.json["response"]["reauth_required"]
    assert not response.json["response"]["has_webauthn_verify_credential"]

    # the us-verify form should NOT have the webauthn verify form attached
    response = client.get("us-verify")
    assert b'action="/wan-verify"' not in response.data


def test_setup_delete(app, client, get_message):
    set_email(app)
    us_authenticate(client)
    response = client.get("us-setup")
    # Email should be in delete options since we just set that up.
    assert all(
        i in response.data
        for i in [b"delete_method-0", b"chosen_method-0", b"chosen_method-1"]
    )
    response = client.post("us-setup", data=dict(delete_method="email"))

    response = client.get("us-setup")
    # All should be in possible setups.
    assert all(
        i in response.data
        for i in [b"chosen_method-0", b"chosen_method-1", b"chosen_method-2"]
    )

    response = client.post("us-setup", json=dict(delete_method="email"))
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "US_METHOD_NOT_AVAILABLE"
    )


def test_setup_delete_json(app, client, get_message):
    recorded = []

    @us_profile_changed.connect_via(app)
    def pc(sender, user, methods, delete, **kwargs):
        if "sms" in methods:
            if delete:
                assert not user.us_phone_number
                recorded.append("delete")
            else:
                assert user.us_phone_number == "+16505551212"
                recorded.append("setup")

    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    set_email(app)
    us_authenticate(client)
    response = client.get("us-setup", headers=headers)
    # Email should be in delete options since we just set that up.
    assert "email" in response.json["response"]["active_methods"]

    response = client.post("us-setup", json=dict(delete_method="email"))
    assert response.status_code == 200

    response = client.get("us-setup", headers=headers)
    assert response.json["response"]["active_methods"] == ["password"]

    response = client.post("us-setup", json=dict(delete_method="email"))
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "US_METHOD_NOT_AVAILABLE"
    )

    # setup and delete SMS
    sms_sender = SmsSenderFactory.createSender("test")
    response = client.post(
        "us-setup",
        json=dict(chosen_method="sms", phone="650-555-1212"),
        headers=headers,
    )
    assert response.status_code == 200
    state = response.json["response"]["state"]
    assert state
    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post(
        "/us-setup/" + state, json=dict(passcode=code), headers=headers
    )
    assert response.status_code == 200
    assert response.json["response"]["chosen_method"] == "sms"
    assert response.json["response"]["phone"] == "+16505551212"

    # verify SMS in active methods
    response = client.get("/us-setup", headers=headers)
    assert response.status_code == 200
    assert set(response.json["response"]["active_methods"]) == {"sms", "password"}

    # delete SMS
    response = client.post("/us-setup", json=(dict(delete_method="sms")))
    assert response.status_code == 200
    response = client.get("/us-setup", headers=headers)
    assert response.json["response"]["active_methods"] == ["password"]
    assert recorded[0] == "setup"
    assert recorded[1] == "delete"


def test_setup_delete_multi_json(app, client, get_message):
    recorded = []

    @us_profile_changed.connect_via(app)
    def pc(sender, user, methods, delete, **kwargs):
        recorded.append((delete, methods))

    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    set_email(app)
    set_phone(app)
    us_authenticate(client)
    response = client.get("us-setup", headers=headers)
    # Email and sms should be in delete options since we just set that up.
    assert set(response.json["response"]["active_methods"]) == {
        "sms",
        "password",
        "email",
    }

    response = client.post("us-setup", json=dict(delete_method=["email", "sms"]))
    assert response.status_code == 200

    response = client.get("us-setup", headers=headers)
    assert response.json["response"]["active_methods"] == ["password"]
    assert len(recorded) == 1
    assert set(recorded[0][1]) == {"sms", "email"}


@pytest.mark.settings(return_generic_responses=True)
def test_generic_response(app, client, get_message):
    # test not-setup choice
    data = dict(identity="matt@lp.com", chosen_method="email")
    response = client.post("/us-signin/send-code", data=data, follow_redirects=True)
    assert get_message("GENERIC_US_SIGNIN") in response.data

    # for JSON still return 200 as if everything is fine and a code was sent.
    response = client.post("/us-signin/send-code", json=data)
    assert response.status_code == 200
    assert not any(e in response.json["response"].keys() for e in ["error", "errors"])

    # Correct method should return same thing
    set_phone(app)
    data = dict(identity="matt@lp.com", chosen_method="sms")
    response = client.post("/us-signin/send-code", data=data, follow_redirects=True)
    assert get_message("GENERIC_US_SIGNIN") in response.data

    # for JSON still return 200 as if everything is fine and a code was sent.
    response = client.post("/us-signin/send-code", json=data)
    assert response.status_code == 200
    assert not any(
        e in response.json["response"].keys() for e in ["field_errors", "errors"]
    )

    # Unknown identity should return same thing
    data = dict(identity="matt2@lp.com", chosen_method="email")
    response = client.post("/us-signin/send-code", data=data, follow_redirects=True)
    assert get_message("GENERIC_US_SIGNIN") in response.data

    # for JSON still return 200 as if everything is fine and a code was sent.
    response = client.post("/us-signin/send-code", json=data)
    assert response.status_code == 200
    assert not any(
        e in response.json["response"].keys() for e in ["field_errors", "errors"]
    )

    #
    # Now test us-signin itself
    #
    data = dict(identity="matt@lp.com", code="12345")
    response = client.post("/us-signin", data=data)
    assert get_message("GENERIC_AUTHN_FAILED") in response.data

    data = dict(identity="matt@lp.com", code="12345")
    response = client.post("/us-signin", json=data)
    assert response.status_code == 400
    assert list(response.json["response"]["field_errors"].keys()) == ["null"]
    assert len(response.json["response"]["field_errors"]["null"]) == 1
    assert response.json["response"]["field_errors"]["null"][0].encode(
        "utf-8"
    ) == get_message("GENERIC_AUTHN_FAILED")
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "GENERIC_AUTHN_FAILED"
    )

    # same with unknown user
    data = dict(identity="matt2@lp.com", code="12345")
    response = client.post("/us-signin", data=data)
    assert get_message("GENERIC_AUTHN_FAILED") in response.data

    data = dict(identity="matt2@lp.com", code="12345")
    response = client.post("/us-signin", json=data)
    assert response.status_code == 400
    assert list(response.json["response"]["field_errors"].keys()) == ["null"]
    assert len(response.json["response"]["field_errors"]["null"]) == 1
    assert response.json["response"]["field_errors"]["null"][0].encode(
        "utf-8"
    ) == get_message("GENERIC_AUTHN_FAILED")
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "GENERIC_AUTHN_FAILED"
    )

    #
    # Test /us-verify-link
    #
    response = client.get(
        "us-verify-link?email=matt42@lp.com&code=12345", follow_redirects=True
    )
    assert get_message("GENERIC_AUTHN_FAILED") in response.data

    # Try bad code
    response = client.get(
        "us-verify-link?email=matt@lp.com&code=12345", follow_redirects=True
    )
    assert get_message("GENERIC_AUTHN_FAILED") in response.data


@pytest.mark.settings(url_prefix="/auth", us_signin_replaces_login=True)
def test_propagate_next(app, client):
    # verify we propagate the ?next param all the way through a unified signin
    # Also test blueprint prefix since we rarely actually test that.
    set_phone(app)
    with capture_send_code_requests() as codes:
        response = client.get("profile", follow_redirects=True)
        assert "?next=/profile" in response.request.url
        signin_url = get_form_action(response, 0)
        sendcode_url = get_form_action(response, 1)
        response = client.post(
            sendcode_url, data=dict(identity="matt@lp.com", chosen_method="sms")
        )
        data = dict(identity="matt@lp.com", passcode=codes[0]["login_token"])
        response = client.post(signin_url, data=data, follow_redirects=False)
        assert "/profile" in response.location


@pytest.mark.two_factor()
@pytest.mark.settings(url_prefix="/auth", us_signin_replaces_login=True)
def test_propagate_next_tf(app, client):
    # test next is propagated with a second factor
    response = client.post(
        "/auth/login", json=dict(identity="matt@lp.com", passcode="password")
    )
    sms_sender = setup_tf_sms(client, url_prefix=app.config["SECURITY_URL_PREFIX"])
    logout(client, endpoint="/auth/logout")

    response = client.get("/profile", follow_redirects=True)
    assert "?next=/profile" in response.request.url
    signin_url = get_form_action(response, 0)
    response = client.post(
        signin_url,
        data=dict(identity="matt@lp.com", passcode="password"),
        follow_redirects=True,
    )
    sendcode_url = get_form_action(response, 0)
    response = client.post(
        sendcode_url,
        data=dict(code=sms_sender.messages[0].split()[-1]),
        follow_redirects=True,
    )
    assert b"Profile Page" in response.data
