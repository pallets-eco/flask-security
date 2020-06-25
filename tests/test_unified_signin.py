"""
    test_unified_signin
    ~~~~~~~~~~~~~~~~~~~

    Unified signin tests

    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

"""

from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import Mock
import re
import time
from urllib.parse import parse_qsl, urlsplit

import pytest
from flask import Flask
from tests.test_utils import (
    SmsBadSender,
    SmsTestSender,
    authenticate,
    capture_flashes,
    capture_reset_password_requests,
    logout,
)

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


def set_phone(app, email="matt@lp.com", phone="650-273-3780"):
    # A quick way to 'setup' SMS
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email=email)
        totp_secret = app.security._totp_factory.generate_totp_secret()
        app.security.datastore.us_set(user, "sms", totp_secret, phone)
        app.security.datastore.commit()


def test_simple_signin(app, clients, get_message):
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
    data = dict(identity="tiya@lp.com", chosen_method="email")
    response = clients.post("/us-signin/send-code", data=data, follow_redirects=True)
    assert b"Code has been sent" not in response.data
    assert get_message("DISABLED_ACCOUNT") in response.data

    with capture_send_code_requests() as requests:
        with app.mail.record_messages() as outbox:
            response = clients.post(
                "/us-signin/send-code",
                data=dict(identity="matt@lp.com", chosen_method="email"),
                follow_redirects=True,
            )
            assert response.status_code == 200
            assert b"Sign In" in response.data
    assert len(requests) == 1
    assert len(outbox) == 1

    # try bad code
    response = clients.post(
        "/us-signin",
        data=dict(identity="matt@lp.com", passcode="blahblah"),
        follow_redirects=True,
    )
    assert get_message("INVALID_PASSWORD_CODE") in response.data

    # Correct code
    assert "remember_token" not in [c.name for c in clients.cookie_jar]
    assert "session" not in [c.name for c in clients.cookie_jar]
    response = clients.post(
        "/us-signin",
        data=dict(identity="matt@lp.com", passcode=requests[0]["token"]),
        follow_redirects=False,
    )
    assert "remember_token" not in [c.name for c in clients.cookie_jar]
    assert "email" in auths[0][1]

    response = clients.get("/profile", follow_redirects=False)
    assert response.status_code == 200

    logout(clients)
    response = clients.get("/profile", follow_redirects=False)
    assert "/login?next=%2Fprofile" in response.location

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
    assert "remember_token" in [c.name for c in clients.cookie_jar]
    assert "sms" in auths[1][1]

    response = clients.get("/profile", follow_redirects=False)
    assert response.status_code == 200

    logout(clients)
    assert "remember_token" not in [c.name for c in clients.cookie_jar]


def test_simple_signin_json(app, client_nc, get_message):
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
            with app.mail.record_messages() as outbox:
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
        assert len(outbox) == 1

        # try bad code
        response = client_nc.post(
            "/us-signin",
            json=dict(identity="matt@lp.com", passcode="blahblah"),
            headers=headers,
            follow_redirects=True,
        )
        assert response.status_code == 400
        assert response.json["response"]["errors"]["passcode"][0].encode(
            "utf-8"
        ) == get_message("INVALID_PASSWORD_CODE")

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
        response = client_nc.get("/profile", headers=headers, follow_redirects=False)
        assert response.status_code == 401

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
    assert response.json["response"]["errors"]["chosen_method"][0].encode(
        "utf-8"
    ) == get_message("US_METHOD_NOT_AVAILABLE")
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
    assert response.json["response"]["errors"]["chosen_method"][0].encode(
        "utf-8"
    ) == get_message("US_METHOD_NOT_AVAILABLE")
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
    assert response.json["response"]["error"].encode("utf-8") == get_message(
        "ANONYMOUS_USER_REQUIRED"
    )


@pytest.mark.settings(us_email_subject="Code For You")
def test_verify_link(app, client, get_message):
    auths = []

    @user_authenticated.connect_via(app)
    def authned(myapp, user, **extra_args):
        auths.append((user.email, extra_args["authn_via"]))

    with app.mail.record_messages() as outbox:
        response = client.post(
            "/us-signin/send-code",
            data=dict(identity="matt@lp.com", chosen_method="email"),
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Sign In" in response.data

    assert outbox[0].recipients == ["matt@lp.com"]
    assert outbox[0].sender == "no-reply@localhost"
    assert outbox[0].subject == "Code For You"
    matcher = re.match(
        r".*(http://[^\s*]*).*", outbox[0].body, re.IGNORECASE | re.DOTALL
    )
    magic_link = matcher.group(1)

    # Try with no code
    response = client.get("us-verify-link?email=matt@lp.com", follow_redirects=False)
    assert response.location == "http://localhost/us-signin"
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
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200


@pytest.mark.settings(
    redirect_host="localhost:8081",
    redirect_behavior="spa",
    login_error_view="/login-error",
    post_login_view="/post-login",
)
def test_verify_link_spa(app, client, get_message):
    # N.B. we use client here since this only works/ is supported if using
    # sessions.
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    with app.mail.record_messages() as outbox:
        response = client.post(
            "/us-signin/send-code",
            json=dict(identity="matt@lp.com", chosen_method="email"),
            headers=headers,
        )
        assert response.status_code == 200

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

    response = client.get("/profile", headers=headers)
    assert response.status_code == 200


def test_setup(app, client, get_message):
    us_authenticate(client)
    response = client.get("us-setup")
    assert all(
        i in response.data
        for i in [b"chosen_method-0", b"chosen_method-1", b"chosen_method-2"]
    )

    # test missing phone
    response = client.post("us-setup", data=dict(chosen_method="sms", phone=""))
    assert response.status_code == 200
    assert get_message("PHONE_INVALID") in response.data

    # test invalid phone
    response = client.post("us-setup", data=dict(chosen_method="sms", phone="555-1212"))
    assert response.status_code == 200
    assert get_message("PHONE_INVALID") in response.data
    assert b"Code has been sent" not in response.data

    sms_sender = SmsSenderFactory.createSender("test")
    response = client.post(
        "us-setup", data=dict(chosen_method="sms", phone="650-555-1212")
    )
    assert response.status_code == 200
    assert b"Submit Code" in response.data
    assert b"Code has been sent" in response.data
    matcher = re.match(
        r'.*<form action="([^\s]*)".*',
        response.data.decode("utf-8"),
        re.IGNORECASE | re.DOTALL,
    )
    verify_url = matcher.group(1)

    # Try invalid code
    response = client.post(verify_url, data=dict(passcode=12345), follow_redirects=True)
    assert get_message("INVALID_PASSWORD_CODE") in response.data

    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post(verify_url, data=dict(passcode=code), follow_redirects=True)
    assert response.status_code == 200
    assert get_message("US_SETUP_SUCCESSFUL") in response.data


def test_setup_email(app, client, get_message):
    # setup with email - make sure magic link isn't sent and code is.
    us_authenticate(client)
    with app.mail.record_messages() as outbox:
        response = client.post("us-setup", data=dict(chosen_method="email"))
        assert response.status_code == 200
        assert b"Code has been sent" in response.data

        matcher = re.match(
            r'.*<form action="([^\s]*)".*',
            response.data.decode("utf-8"),
            re.IGNORECASE | re.DOTALL,
        )
        verify_url = matcher.group(1)

    # verify no magic link
    matcher = re.match(
        r".*(http://[^\s*]*).*", outbox[0].body, re.IGNORECASE | re.DOTALL
    )
    assert not matcher
    # grab real code
    matcher = re.match(r".*code: ([0-9]+).*", outbox[0].body, re.IGNORECASE | re.DOTALL)
    code = matcher.group(1)
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
    def pc(sender, user, method):
        assert method == "sms"
        assert user.us_phone_number == "+16505551212"

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
    assert response.json["response"]["active_methods"] == ["email"]

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
    assert response.json["response"]["errors"]["passcode"][0].encode(
        "utf-8"
    ) == get_message("INVALID_PASSWORD_CODE")
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
    assert set(response.json["response"]["active_methods"]) == {"email", "sms"}

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
    us_enabled_methods=["email", "sms"], user_identity_attributes=UIA_EMAIL_PHONE,
)
def test_setup_json_no_session(app, client_nc, get_message):
    # Test that with normal config freshness is required so must have session.
    token = us_authenticate(client_nc)
    headers = {
        "Authentication-Token": token,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    response = client_nc.get("/us-setup", headers=headers)
    assert response.status_code == 401


def test_setup_bad_token(app, client, get_message):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    us_authenticate(client)

    # bogus state
    response = client.post(
        "/us-setup/not a token", json=dict(passcode=12345), headers=headers
    )
    assert response.status_code == 400
    assert response.json["response"]["error"].encode("utf-8") == get_message(
        "API_ERROR"
    )

    # same w/o json
    response = client.post(
        "/us-setup/not a token", data=dict(passcode=12345), follow_redirects=True
    )
    assert get_message("API_ERROR") in response.data


@pytest.mark.settings(us_setup_within="1 milliseconds")
def test_setup_timeout(app, client, get_message):
    # Test setup timeout
    us_authenticate(client)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    sms_sender = SmsSenderFactory.createSender("test")
    response = client.post(
        "us-setup",
        json=dict(chosen_method="sms", phone="650-555-1212"),
        headers=headers,
    )
    assert response.status_code == 200
    state = response.json["response"]["state"]
    time.sleep(1)

    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post(
        "/us-setup/" + state, json=dict(passcode=code), headers=headers
    )
    assert response.status_code == 400
    assert response.json["response"]["error"].encode("utf-8") == get_message(
        "US_SETUP_EXPIRED", within=app.config["SECURITY_US_SETUP_WITHIN"]
    )


@pytest.mark.settings(freshness=timedelta(minutes=0))
def test_verify(app, client, get_message):
    # Test setup when re-authenticate required
    # With  freshness set to 0 - the first call should require reauth (by
    # redirecting); but the second should work due to grace period.
    us_authenticate(client)
    response = client.get("us-setup", follow_redirects=False)
    verify_url = response.location
    assert (
        verify_url
        == "http://localhost/us-verify?next=http%3A%2F%2Flocalhost%2Fus-setup"
    )
    logout(client)
    us_authenticate(client)

    response = client.get("us-setup", follow_redirects=True)
    form_response = response.data.decode("utf-8")
    assert "Please re-authenticate" in form_response
    matcher = re.match(
        r'.*formaction="([^"]*)".*', form_response, re.IGNORECASE | re.DOTALL
    )
    send_code_url = matcher.group(1)

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
    assert set(response.json["response"]["code_methods"]) == {
        "email",
        "sms",
    }

    response = client.post(
        "us-verify/send-code", json=dict(chosen_method="orb"), headers=headers,
    )
    assert response.status_code == 400

    # Verify using SMS
    sms_sender = SmsSenderFactory.createSender("test")
    set_phone(app)
    response = client.post(
        "us-verify/send-code", json=dict(chosen_method="sms"), headers=headers,
    )
    assert response.status_code == 200

    # Try bad code
    response = client.post("us-verify", json=dict(passcode=42), headers=headers)
    assert response.status_code == 400
    assert response.json["response"]["errors"]["passcode"][0].encode(
        "utf-8"
    ) == get_message("INVALID_PASSWORD_CODE")

    response = client.post("us-verify", json=dict(passcode=None), headers=headers)
    assert response.status_code == 400
    assert response.json["response"]["errors"]["passcode"][0].encode(
        "utf-8"
    ) == get_message("INVALID_PASSWORD_CODE")

    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post("us-verify", json=dict(passcode=code), headers=headers)
    assert response.status_code == 200

    app.config["SECURITY_FRESHNESS"] = timedelta(minutes=60)
    response = client.get("us-setup", headers=headers)
    assert response.status_code == 200


@pytest.mark.settings(freshness=timedelta(minutes=-1))
def test_setup_nofresh(app, client, get_message):
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
    response = client.get("/us-signin/send-code", headers=headers)
    assert response.json["response"]["available_methods"] == ["sms"]

    # verify json error
    response = client.post(
        "/us-signin/send-code",
        json=dict(identity="matt@lp.com", chosen_method="email"),
        headers=headers,
        follow_redirects=True,
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"]["chosen_method"][0].encode(
        "utf-8"
    ) == get_message("US_METHOD_NOT_AVAILABLE")

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
    assert response.json["response"]["errors"]["chosen_method"][0].encode(
        "utf-8"
    ) == get_message("US_METHOD_NOT_AVAILABLE")

    response = client.post(
        "/us-setup",
        data=dict(email="matt@lp.com", chosen_method="authenticators"),
        follow_redirects=True,
    )
    assert b"Not a valid choice" in response.data


def test_setup_new_totp(app, client, get_message):
    # us-setup should generate a new totp secret for each setup
    # Verify  existing cods no longer work
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
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    us_authenticate(client, identity="gal@lp.com")
    response = client.post(
        "us-setup", json=dict(chosen_method="authenticator"), headers=headers
    )
    assert response.status_code == 200
    state = response.json["response"]["state"]

    # Now request code. We can't test the qrcode easily - but we can get the totp_secret
    # that goes into the qrcode and make sure that works
    mtf = Mock(wraps=app.security._totp_factory)
    app.security.totp_factory(mtf)
    qrcode_page_response = client.get("/us-qrcode/" + state, follow_redirects=True)
    assert mtf.get_totp_uri.call_count == 1
    (username, totp_secret), _ = mtf.get_totp_uri.call_args
    assert username == "gal@lp.com"
    assert b"svg" in qrcode_page_response.data

    # Generate token from passed totp_secret and confirm setup
    code = app.security._totp_factory.generate_totp_password(totp_secret)
    response = client.post(
        "/us-setup/" + state, json=dict(passcode=code), headers=headers
    )
    assert response.status_code == 200
    assert response.json["response"]["chosen_method"] == "authenticator"


def test_next(app, client, get_message):
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
    assert response.location == "http://localhost/post_login"

    logout(client)
    response = client.post(
        "/us-signin",
        data=dict(
            identity="matt@lp.com", passcode=requests[0]["token"], next="/post_login"
        ),
        follow_redirects=False,
    )
    assert response.location == "http://localhost/post_login"


@pytest.mark.registerable()
@pytest.mark.confirmable()
def test_confirmable(app, client, get_message):
    # Verify can't log in if need confirmation.
    data = dict(
        email="dude@lp.com", password="password", password_confirm="password", next=""
    )
    response = client.post("/register", data=data, follow_redirects=True)
    assert response.status_code == 200

    # try to get a code - this should succeed
    with capture_send_code_requests() as requests:
        response = client.post(
            "/us-signin/send-code",
            data=dict(identity="dude@lp.com", chosen_method="email"),
            follow_redirects=True,
        )
        assert response.status_code == 200

    response = client.post(
        "/us-signin",
        data=dict(identity="dude@lp.com", passcode=requests[0]["token"]),
        follow_redirects=True,
    )
    assert get_message("CONFIRMATION_REQUIRED") in response.data

    # Verify not authenticated
    response = client.get("/profile", follow_redirects=False)
    assert "/login?next=%2Fprofile" in response.location


@pytest.mark.registerable()
@pytest.mark.recoverable()
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

    assert get_message("PASSWORD_RESET") in response.data

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
    assert "remember_token" in [c.name for c in client.cookie_jar]
    assert "password" in auths[0][1]

    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200


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
    assert b"Your token has been confirmed" in response.data


@pytest.mark.two_factor()
@pytest.mark.settings(two_factor_required=True)
def test_tf_link(app, client, get_message):
    # Verify two-factor required when using magic link
    with app.mail.record_messages() as outbox:
        response = client.post(
            "/us-signin/send-code",
            data=dict(identity="matt@lp.com", chosen_method="email"),
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Sign In" in response.data

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
    with app.mail.record_messages() as outbox:
        response = client.post(
            "/us-signin/send-code",
            data=dict(identity="matt@lp.com", chosen_method="email"),
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Sign In" in response.data

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
    matcher = re.match(
        r'.*<form action="([^\s]*)".*',
        response.data.decode("utf-8"),
        re.IGNORECASE | re.DOTALL,
    )
    verify_url = matcher.group(1)
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
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200


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
    assert response.json["response"]["errors"]["chosen_method"][0].encode(
        "utf-8"
    ) == get_message("FAILED_TO_SEND_CODE")

    # Now test setup
    us_authenticate(client)
    data = dict(chosen_method="sms", phone="650-555-1212")
    response = client.post("us-setup", data=data)
    assert get_message("FAILED_TO_SEND_CODE") in response.data

    response = client.post("us-setup", json=data, headers=headers)
    assert response.status_code == 500
    assert response.json["response"]["errors"]["chosen_method"][0].encode(
        "utf-8"
    ) == get_message("FAILED_TO_SEND_CODE")


@pytest.mark.registerable()
def test_replace_send_code(app, get_message):
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
    assert b"Open your authenticator app" in response.data

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
    state = response.json["response"]["state"]

    # Now request code. We can't test the qrcode easily - but we can get the totp_secret
    # that goes into the qrcode and make sure that works
    mtf = Mock(wraps=app.security._totp_factory)
    app.security.totp_factory(mtf)
    client.get("/us-qrcode/" + state, follow_redirects=True)
    assert mtf.get_totp_uri.call_count == 1
    (username, totp_secret), _ = mtf.get_totp_uri.call_args

    # Generate token from passed totp_secret and confirm setup
    code = app.security._totp_factory.generate_totp_password(totp_secret)
    response = client.post(
        "/us-setup/" + state, json=dict(passcode=code), headers=headers
    )
    assert response.status_code == 200
    assert response.json["response"]["chosen_method"] == "authenticator"

    # success - totp_secret in DB should have been saved
    with app.app_context():
        user = app.security.datastore.find_user(email="dave@lp.com")
        ts = app.security.datastore.us_get_totp_secrets(user)
        assert totp_secret == ts["authenticator"]

    # Ok - setup again, this time don't verify and
    # make sure totp_secret in DB doesn't change
    response = client.post(
        "us-setup", json=dict(chosen_method="authenticator"), headers=headers
    )
    assert response.status_code == 200
    state = response.json["response"]["state"]

    # Now request code. We can't test the qrcode easily - but we can get the totp_secret
    # that goes into the qrcode and make sure that works
    mtf = Mock(wraps=app.security._totp_factory)
    app.security.totp_factory(mtf)
    client.get("/us-qrcode/" + state, follow_redirects=True)
    assert mtf.get_totp_uri.call_count == 1
    (username, new_totp_secret), _ = mtf.get_totp_uri.call_args
    # Should generate a new totp secret for each setup
    assert totp_secret != new_totp_secret

    # validate with wrong code
    response = client.post(
        "/us-setup/" + state, json=dict(passcode=123345), headers=headers
    )
    assert response.status_code == 400

    # Make sure totp_secret in DB didn't change
    with app.app_context():
        user = app.security.datastore.find_user(email="dave@lp.com")
        ts = app.security.datastore.us_get_totp_secrets(user)
        assert totp_secret == ts["authenticator"]

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
        assert totp_secret == ts["authenticator"]
