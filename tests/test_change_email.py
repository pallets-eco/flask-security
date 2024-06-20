"""
    test_change_email
    ~~~~~~~~~~~~~~~~~

    Change email functionality tests

    :copyright: (c) 2024-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from contextlib import contextmanager
from datetime import date, timedelta
import re
from urllib.parse import urlsplit

import pytest
from freezegun import freeze_time
from tests.test_utils import (
    authenticate,
    capture_flashes,
    is_authenticated,
    json_authenticate,
    logout,
)
from flask_security import hash_password
from flask_security.signals import (
    change_email_instructions_sent,
    change_email_confirmed,
)

pytestmark = pytest.mark.change_email()


@contextmanager
def capture_change_email_requests():
    change_email_requests = []

    def _on(app, **data):
        change_email_requests.append(data)

    change_email_instructions_sent.connect(_on)

    try:
        yield change_email_requests
    finally:
        change_email_instructions_sent.disconnect(_on)


@pytest.mark.settings(change_email_error_view="/change-email")
def test_ce(app, clients, get_message):
    client = clients

    @change_email_confirmed.connect_via(app)
    def _on(app, **kwargs):
        assert kwargs["old_email"] == "matt@lp.com"
        assert kwargs["user"].email == "matt2@lp.com"

    authenticate(client, email="matt@lp.com")

    with capture_change_email_requests() as ce_requests:
        response = client.post("/change-email", data={"email": "<EMAIL>"})
        assert get_message("INVALID_EMAIL_ADDRESS") in response.data
        assert not app.mail.outbox

        response = client.post("/change-email", data=dict(email="matt2@lp.com"))
        msg = get_message("CHANGE_EMAIL_SENT", email="matt2@lp.com")
        assert msg in response.data
        assert "matt2@lp.com" == ce_requests[0]["new_email"]
        token = ce_requests[0]["token"]
    assert len(app.mail.outbox) == 1
    assert app.config["SECURITY_CHANGE_EMAIL_WITHIN"] in app.mail.outbox[0].body

    response = client.get("/change-email/" + token, follow_redirects=True)
    assert get_message("CHANGE_EMAIL_CONFIRMED") in response.data
    assert is_authenticated(client, get_message)

    logout(client)
    authenticate(client, email="matt2@lp.com")
    assert is_authenticated(client, get_message)

    # try using link again - should fail
    with capture_flashes() as flashes:
        client.get("/change-email/" + token, follow_redirects=True)
    assert flashes[0]["message"].encode("utf-8") == get_message("API_ERROR")


def test_ce_json(app, client, get_message):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    @change_email_confirmed.connect_via(app)
    def _on(app, **kwargs):
        assert kwargs["old_email"] == "matt@lp.com"
        assert kwargs["user"].email == "matt2@lp.com"

    json_authenticate(client, email="matt@lp.com")

    with capture_change_email_requests() as ce_requests:
        response = client.post("/change-email", json={"email": "<EMAIL>"})
        assert response.json["response"]["errors"][0].encode("utf=8") == get_message(
            "INVALID_EMAIL_ADDRESS"
        )
        assert not app.mail.outbox

        response = client.post("/change-email", json=dict(email="matt2@lp.com"))
        assert response.status_code == 200
        assert response.json["response"]["current_email"] == "matt@lp.com"
        assert "matt2@lp.com" == ce_requests[0]["new_email"]
        token = ce_requests[0]["token"]
    assert len(app.mail.outbox) == 1

    response = client.get(
        "/change-email/" + token, headers=headers, follow_redirects=True
    )
    assert get_message("CHANGE_EMAIL_CONFIRMED") in response.data
    assert is_authenticated(client, get_message)

    logout(client)
    authenticate(client, email="matt2@lp.com")
    assert is_authenticated(client, get_message)


@pytest.mark.settings(
    change_email_within="1 milliseconds", change_email_error_view="/change-email"
)
def test_expired_token(client, get_message):
    # Note that we need relatively new-ish date since session cookies also expire.
    with freeze_time(date.today() + timedelta(days=-1)):
        authenticate(client, email="matt@lp.com")
        with capture_change_email_requests() as ce_requests:
            client.post("/change-email", data=dict(email="matt2@lp.com"))

        assert "matt2@lp.com" == ce_requests[0]["new_email"]
        token = ce_requests[0]["token"]

    response = client.get("/change-email/" + token, follow_redirects=True)
    msg = get_message("CHANGE_EMAIL_EXPIRED", within="1 milliseconds")
    assert msg in response.data


def test_template(app, client, get_message):
    # Check contents of email template - this uses a test template
    # in order to check all context vars since the default template
    # doesn't have all of them.

    authenticate(client, email="matt@lp.com")
    with capture_change_email_requests() as ce_requests:
        client.post("/change-email", data=dict(email="matt2@lp.com"))
        # check email
        outbox = app.mail.outbox
        assert outbox[0].to[0] == "matt2@lp.com"
        matcher = re.findall(r"\w+:.*", outbox[0].body, re.IGNORECASE)
        # should be 4 - link, email, token, config item
        assert matcher[1].split(":")[1] == "matt@lp.com"
        assert matcher[2].split(":")[1] == ce_requests[0]["token"]
        assert matcher[3].split(":")[1] == "True"  # register_blueprint
        assert matcher[4].split(":")[1] == "2 hours"

        # check link
        _, link = matcher[0].split(":", 1)
        response = client.get(link, follow_redirects=True)
        assert get_message("CHANGE_EMAIL_CONFIRMED") in response.data


@pytest.mark.settings(return_generic_responses=True)
def test_generic_response(app, client, get_message):
    authenticate(client, email="matt@lp.com")
    with capture_change_email_requests():
        # first try bad formatted email - should get detailed error
        response = client.post("/change-email", json={"email": "<EMAIL>"})
        assert response.json["response"]["errors"][0].encode("utf=8") == get_message(
            "INVALID_EMAIL_ADDRESS"
        )

        # try existing email - should get same response as if it 'worked'
        response = client.post("/change-email", data=dict(email="gal@lp.com"))
        msg = get_message("CHANGE_EMAIL_SENT", email="gal@lp.com")
        assert msg in response.data
        # but no email was actually sent
        assert not app.mail.outbox


@pytest.mark.settings(
    redirect_host="myui.com:8090",
    redirect_behavior="spa",
    post_change_email_view="/change-email-redirect",
    change_email_error_view="/change-email-error",
)
def test_spa_get(app, client, get_message):
    json_authenticate(client, email="matt@lp.com")

    with capture_change_email_requests() as ce_requests:
        response = client.post("/change-email", data=dict(email="matt2@lp.com"))
        msg = get_message("CHANGE_EMAIL_SENT", email="matt2@lp.com")
        assert msg in response.data
        assert "matt2@lp.com" == ce_requests[0]["new_email"]
        token = ce_requests[0]["token"]
    response = client.get("/change-email/" + token, follow_redirects=False)
    assert response.status_code == 302
    split = urlsplit(response.headers["Location"])
    assert "myui.com:8090" == split.netloc
    assert "/change-email-redirect" == split.path

    # again - should be an error
    response = client.get("/change-email/" + token, follow_redirects=False)
    assert response.status_code == 302
    split = urlsplit(response.headers["Location"])
    assert "myui.com:8090" == split.netloc
    assert "/change-email-error" == split.path


@pytest.mark.settings(change_email_error_view="/change-email")
def test_ce_race(app, client, get_message):
    # test that if an email is taken between the link being sent and
    # the user confirming - they get an error

    authenticate(client, email="matt@lp.com")

    with capture_change_email_requests() as ce_requests:
        client.post("/change-email", data=dict(email="matt2@lp.com"))
        token = ce_requests[0]["token"]

    with app.app_context():
        app.security.datastore.create_user(
            email="matt2@lp.com",
            password=hash_password("password"),
        )
        app.security.datastore.commit()
    with capture_flashes() as flashes:
        client.get("/change-email/" + token, follow_redirects=True)
    assert flashes[0]["message"].encode("utf-8") == get_message("API_ERROR")
