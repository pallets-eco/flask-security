# -*- coding: utf-8 -*-
"""
    test_unified_signin
    ~~~~~~~~~~~~~~~~~~~

    Unified signin tests

    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

"""

from contextlib import contextmanager
import json

try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock
import re
import time

import pytest
from flask import Flask
from utils import SmsTestSender, logout

from flask_security import (
    SmsSenderFactory,
    UserMixin,
    us_profile_changed,
    us_security_token_sent,
)
from flask_security.utils import capture_flashes

try:
    from urlparse import parse_qsl, urlsplit
except ImportError:  # pragma: no cover
    from urllib.parse import parse_qsl, urlsplit

pytestmark = pytest.mark.unified_signin()

SmsSenderFactory.senders["test"] = SmsTestSender


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


def authenticate(client, identity="matt@lp.com"):
    with capture_send_code_requests() as requests:
        response = client.post(
            "/us-send-code",
            data=json.dumps(dict(identity=identity, chosen_method="email")),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 200

    response = client.post(
        "/us-signin?include_auth_token",
        data=json.dumps(dict(identity=identity, passcode=requests[0]["token"])),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    return response.jdata["response"]["user"]["authentication_token"]


def set_phone(app, email="matt@lp.com", phone="650-273-3780"):
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email=email)
        user.us_phone_number = phone
        app.security.datastore.put(user)
        app.security.datastore.commit()


def test_simple_login(app, client, get_message):
    # Test missing choice
    data = dict(identity="matt@lp.com")
    response = client.post("/us-send-code", data=data, follow_redirects=True)
    assert get_message("US_METHOD_NOT_AVAILABLE") in response.data

    # Test login using invalid email
    data = dict(identity="nobody@lp.com", chosen_method="email")
    response = client.post("/us-send-code", data=data, follow_redirects=True)
    assert get_message("US_SPECIFY_IDENTITY") in response.data

    # test disabled account
    data = dict(identity="tiya@lp.com", chosen_method="email")
    response = client.post("/us-send-code", data=data, follow_redirects=True)
    assert b"Code has been sent" not in response.data
    assert get_message("DISABLED_ACCOUNT") in response.data

    with capture_send_code_requests() as requests:
        with app.mail.record_messages() as outbox:
            response = client.post(
                "/us-send-code",
                data=dict(identity="matt@lp.com", chosen_method="email"),
                follow_redirects=True,
            )
            assert response.status_code == 200
            assert b"Sign In" in response.data
    assert len(requests) == 1
    assert len(outbox) == 1

    # try bad code
    response = client.post(
        "/us-signin",
        data=dict(identity="matt@lp.com", passcode="blahblah"),
        follow_redirects=True,
    )
    assert get_message("INVALID_PASSWORD") in response.data

    # Correct code
    assert "remember_token" not in [c.name for c in client.cookie_jar]
    assert "session" not in [c.name for c in client.cookie_jar]
    response = client.post(
        "/us-signin",
        data=dict(identity="matt@lp.com", passcode=requests[0]["token"]),
        follow_redirects=False,
    )
    assert "remember_token" not in [c.name for c in client.cookie_jar]

    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200

    logout(client)
    response = client.get("/profile", follow_redirects=False)
    assert "/login?next=%2Fprofile" in response.location

    # login via SMS
    sms_sender = SmsSenderFactory.createSender("test")
    set_phone(app)
    response = client.post(
        "/us-send-code",
        data=dict(identity="matt@lp.com", chosen_method="sms"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Sign In" in response.data

    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post(
        "/us-signin",
        data=dict(identity="matt@lp.com", passcode=code, remember=True),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "remember_token" in [c.name for c in client.cookie_jar]

    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200

    logout(client)
    assert "remember_token" not in [c.name for c in client.cookie_jar]


def test_simple_login_json(app, client_nc, get_message):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    with capture_flashes() as flashes:

        response = client_nc.get("/us-signin", headers=headers)
        assert (
            response.jdata["response"]["methods"]
            == app.config["SECURITY_US_ENABLED_METHODS"]
        )
        assert (
            response.jdata["response"]["identity_attributes"]
            == app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"]
        )

        with capture_send_code_requests() as requests:
            with app.mail.record_messages() as outbox:
                response = client_nc.post(
                    "/us-send-code",
                    data=json.dumps(
                        dict(identity="matt@lp.com", chosen_method="email")
                    ),
                    headers=headers,
                    follow_redirects=True,
                )
                assert response.status_code == 200
                assert "csrf_token" in response.jdata["response"]
                assert "user" not in response.jdata["response"]
        assert len(requests) == 1
        assert len(outbox) == 1

        # try bad code
        response = client_nc.post(
            "/us-signin",
            data=json.dumps(dict(identity="matt@lp.com", passcode="blahblah")),
            headers=headers,
            follow_redirects=True,
        )
        assert response.status_code == 400
        assert response.jdata["response"]["errors"]["passcode"][0].encode(
            "utf-8"
        ) == get_message("INVALID_PASSWORD")

        # Login successfully with code
        response = client_nc.post(
            "/us-signin?include_auth_token",
            data=json.dumps(
                dict(identity="matt@lp.com", passcode=requests[0]["token"])
            ),
            headers=headers,
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert "authentication_token" in response.jdata["response"]["user"]

        logout(client_nc)
        response = client_nc.get("/profile", headers=headers, follow_redirects=False)
        assert response.status_code == 401

        # login via SMS
        sms_sender = SmsSenderFactory.createSender("test")
        set_phone(app)
        response = client_nc.post(
            "/us-send-code",
            data=json.dumps(dict(identity="matt@lp.com", chosen_method="sms")),
            headers=headers,
            follow_redirects=True,
        )
        assert response.status_code == 200

        code = sms_sender.messages[0].split()[-1].strip(".")
        response = client_nc.post(
            "/us-signin?include_auth_token",
            data=json.dumps(dict(identity="matt@lp.com", passcode=code)),
            headers=headers,
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert "authentication_token" in response.jdata["response"]["user"]
    assert len(flashes) == 0


def test_verify_link(app, client, get_message):
    with app.mail.record_messages() as outbox:
        response = client.post(
            "/us-send-code",
            data=dict(identity="matt@lp.com", chosen_method="email"),
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Sign In" in response.data

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
            "/us-send-code",
            data=json.dumps(dict(identity="matt@lp.com", chosen_method="email")),
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
    authenticate(client)
    response = client.get("us-setup")
    assert all(
        i in response.data
        for i in [b"chosen_method-0", b"chosen_method-1", b"chosen_method-2"]
    )

    # test missing phone
    response = client.post("us-setup", data=dict(chosen_method="sms", phone=""))
    assert response.status_code == 200
    assert get_message("US_PHONE_REQUIRED") in response.data

    sms_sender = SmsSenderFactory.createSender("test")
    response = client.post("us-setup", data=dict(chosen_method="sms", phone="555-1212"))
    assert response.status_code == 200
    assert b"Submit Code" in response.data
    matcher = re.match(
        r'.*<form action="([^\s]*)".*',
        response.data.decode("utf-8"),
        re.IGNORECASE | re.DOTALL,
    )
    verify_url = matcher.group(1)

    # Try invalid code
    response = client.post(verify_url, data=dict(code=12345), follow_redirects=True)
    assert get_message("INVALID_CODE") in response.data

    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post(verify_url, data=dict(code=code), follow_redirects=True)
    assert response.status_code == 200
    assert get_message("US_SETUP_SUCCESSFUL") in response.data


@pytest.mark.settings(
    us_enabled_methods=["email", "sms"],
    user_identity_attributes=["email", "us_phone_number"],
)
def test_setup_json(app, client_nc, get_message):
    @us_profile_changed.connect_via(app)
    def pc(sender, user, method):
        assert method == "sms"
        assert user.us_phone_number == "650-555-1212"

    token = authenticate(client_nc)
    headers = {
        "Authentication-Token": token,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    response = client_nc.get("/us-setup", headers=headers)
    assert response.status_code == 200
    assert response.jdata["response"]["methods"] == ["email", "sms"]

    sms_sender = SmsSenderFactory.createSender("test")
    response = client_nc.post(
        "us-setup",
        data=json.dumps(dict(chosen_method="sms", phone="650-555-1212")),
        headers=headers,
    )
    assert response.status_code == 200
    state = response.jdata["response"]["state"]
    assert state

    # send invalid code
    response = client_nc.post(
        "/us-setup/" + state, data=json.dumps(dict(code=12344)), headers=headers
    )
    assert response.status_code == 400
    assert response.jdata["response"]["errors"]["code"][0].encode(
        "utf-8"
    ) == get_message("INVALID_CODE")
    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client_nc.post(
        "/us-setup/" + state, data=json.dumps(dict(code=code)), headers=headers
    )
    assert response.status_code == 200
    assert response.jdata["response"]["chosen_method"] == "sms"
    assert response.jdata["response"]["phone"] == "650-555-1212"

    # now login with phone
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    sms_sender = SmsSenderFactory.createSender("test")
    response = client_nc.post(
        "/us-send-code",
        data=json.dumps(dict(identity="650-555-1212", chosen_method="sms")),
        headers=headers,
    )
    assert response.status_code == 200
    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client_nc.post(
        "/us-signin?include_auth_token",
        data=json.dumps(dict(identity="matt@lp.com", passcode=code)),
        headers=headers,
    )
    assert response.status_code == 200
    assert "authentication_token" in response.jdata["response"]["user"]


def test_setup_bad_token(app, client, get_message):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    authenticate(client)

    # bogus state
    response = client.post(
        "/us-setup/" + "not a token", data=json.dumps(dict(code=12345)), headers=headers
    )
    assert response.status_code == 400
    assert response.jdata["response"]["error"].encode("utf-8") == get_message(
        "API_ERROR"
    )

    # same w/o json
    response = client.post(
        "/us-setup/" + "not a token", data=dict(code=12345), follow_redirects=True
    )
    assert get_message("API_ERROR") in response.data


@pytest.mark.settings(us_setup_within="1 milliseconds")
def test_setup_timeout(app, client, get_message):
    # Test setup timeout
    authenticate(client)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    sms_sender = SmsSenderFactory.createSender("test")
    response = client.post(
        "us-setup",
        data=json.dumps(dict(chosen_method="sms", phone="555-1212")),
        headers=headers,
    )
    assert response.status_code == 200
    state = response.jdata["response"]["state"]
    time.sleep(1)

    code = sms_sender.messages[0].split()[-1].strip(".")
    response = client.post(
        "/us-setup/" + state, data=json.dumps(dict(code=code)), headers=headers
    )
    assert response.status_code == 400
    assert response.jdata["response"]["error"].encode("utf-8") == get_message(
        "US_SETUP_EXPIRED", within=app.config["SECURITY_US_SETUP_WITHIN"]
    )


@pytest.mark.settings(us_enabled_methods=["sms"])
def test_invalid_method(app, client, get_message):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    response = client.get("/us-signin", headers=headers)
    assert response.jdata["response"]["methods"] == ["sms"]
    response = client.get("/us-send-code", headers=headers)
    assert response.jdata["response"]["methods"] == ["sms"]

    # verify json error
    response = client.post(
        "/us-send-code",
        data=json.dumps(dict(identity="matt@lp.com", chosen_method="email")),
        headers=headers,
        follow_redirects=True,
    )
    assert response.status_code == 400
    assert response.jdata["response"]["errors"]["chosen_method"][0].encode(
        "utf-8"
    ) == get_message("US_METHOD_NOT_AVAILABLE")

    # verify form error
    response = client.post(
        "/us-send-code",
        data=dict(identity="matt@lp.com", chosen_method="email"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert get_message("US_METHOD_NOT_AVAILABLE") in response.data


@pytest.mark.settings(us_enabled_methods=["sms", "email"])
def test_invalid_method_setup(app, client, get_message):
    authenticate(client)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    response = client.get("/us-setup", headers=headers)
    assert response.jdata["response"]["methods"] == ["sms", "email"]

    # verify json error
    response = client.post(
        "/us-setup",
        data=json.dumps(dict(email="matt@lp.com", chosen_method="authenticator")),
        headers=headers,
        follow_redirects=True,
    )
    assert response.status_code == 400
    assert response.jdata["response"]["errors"]["chosen_method"][0].encode(
        "utf-8"
    ) == get_message("US_METHOD_NOT_AVAILABLE")

    response = client.post(
        "/us-setup",
        data=dict(email="matt@lp.com", chosen_method="authenticators"),
        follow_redirects=True,
    )
    assert b"Not a valid choice" in response.data


def test_setup_new_totp(app, client, get_message):
    # us-setup has a 'generate new totp-secret' option
    # Verify that works (and existing codes no longer work)
    authenticate(client)

    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    # Start by generating a good code
    sms_sender = SmsSenderFactory.createSender("test")
    response = client.post(
        "us-setup",
        data=json.dumps(dict(chosen_method="sms", phone="555-1212")),
        headers=headers,
    )
    assert response.status_code == 200
    code = sms_sender.messages[0].split()[-1].strip(".")

    # Now send correct value - this should generatea new totp - so the previous 'code'
    # should no longer work
    sms_sender2 = SmsSenderFactory.createSender("test")
    response = client.post(
        "us-setup",
        data=json.dumps(
            dict(chosen_method="sms", phone="555-1212", new_totp_secret=True)
        ),
        headers=headers,
    )
    assert response.status_code == 200
    state = response.jdata["response"]["state"]
    # Use old code
    response = client.post(
        "/us-setup/" + state, data=json.dumps(dict(code=code)), headers=headers
    )
    assert response.status_code == 400

    # Use new code
    code = sms_sender2.messages[0].split()[-1].strip(".")
    response = client.post(
        "/us-setup/" + state, data=json.dumps(dict(code=code)), headers=headers
    )
    assert response.status_code == 200
    assert response.jdata["response"]["chosen_method"] == "sms"
    assert response.jdata["response"]["phone"] == "555-1212"


def test_qrcode(app, client, get_message):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    authenticate(client, identity="gal@lp.com")
    response = client.post(
        "us-setup",
        data=json.dumps(dict(chosen_method="authenticator")),
        headers=headers,
    )
    assert response.status_code == 200
    state = response.jdata["response"]["state"]

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
        "/us-setup/" + state, data=json.dumps(dict(code=code)), headers=headers
    )
    assert response.status_code == 200
    assert response.jdata["response"]["chosen_method"] == "authenticator"


def test_next(app, client, get_message):
    with capture_send_code_requests() as requests:
        response = client.post(
            "/us-send-code",
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
            "/us-send-code",
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
