"""
    test_confirmable
    ~~~~~~~~~~~~~~~~

    Confirmable tests
"""

import re
import time
from urllib.parse import parse_qsl, urlsplit

import pytest
from flask import Flask
from wtforms.fields import StringField
from wtforms.validators import Length

from flask_security.core import Security, UserMixin
from flask_security.signals import confirm_instructions_sent, user_confirmed
from flask_security.forms import SendConfirmationForm

from tests.test_utils import (
    authenticate,
    capture_flashes,
    capture_registrations,
    is_authenticated,
    logout,
    populate_data,
)

pytestmark = pytest.mark.confirmable()


@pytest.mark.registerable()
def test_confirmable_flag(app, clients, get_message):
    recorded_confirms = []
    recorded_instructions_sent = []

    @user_confirmed.connect_via(app)
    def on_confirmed(app, user):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        recorded_confirms.append(user)

    @confirm_instructions_sent.connect_via(app)
    def on_instructions_sent(app, **kwargs):
        assert isinstance(app, Flask)
        assert isinstance(kwargs["user"], UserMixin)
        assert isinstance(kwargs["token"], str)
        assert isinstance(kwargs["confirmation_token"], str)
        recorded_instructions_sent.append(kwargs["user"])

    # Test login before confirmation
    email = "dude@lp.com"

    with capture_registrations() as registrations:
        data = dict(email=email, password="awesome sunset", next="")
        response = clients.post("/register", data=data)

    assert response.status_code == 302

    response = authenticate(clients, email=email, password="awesome sunset")
    assert get_message("CONFIRMATION_REQUIRED") in response.data

    # Test invalid token
    response = clients.get("/confirm/bogus", follow_redirects=True)
    assert get_message("INVALID_CONFIRMATION_TOKEN") in response.data

    # Test JSON
    response = clients.post(
        "/confirm",
        json=dict(email="matt@lp.com"),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/json"
    assert "user" not in response.json["response"]
    assert len(recorded_instructions_sent) == 1

    # Test ask for instructions with invalid email
    response = clients.post("/confirm", data=dict(email="bogus@bogus.com"))
    assert get_message("USER_DOES_NOT_EXIST") in response.data

    # Test resend instructions
    response = clients.post("/confirm", data=dict(email=email))
    assert get_message("CONFIRMATION_REQUEST", email=email) in response.data
    assert len(recorded_instructions_sent) == 2

    # Test confirm
    token = registrations[0]["confirm_token"]
    response = clients.get("/confirm/" + token, follow_redirects=False)
    assert len(recorded_confirms) == 1
    assert response.headers.get("Referrer-Policy", None) == "no-referrer"
    response = clients.get(response.location)
    assert get_message("EMAIL_CONFIRMED") in response.data
    # make sure not logged in
    assert not is_authenticated(clients, get_message)

    # Test already confirmed
    response = clients.get("/confirm/" + token, follow_redirects=True)
    assert get_message("ALREADY_CONFIRMED") in response.data
    assert len(recorded_instructions_sent) == 2

    # Test already confirmed when asking for confirmation instructions
    response = clients.get("/confirm")
    assert response.status_code == 200

    response = clients.post("/confirm", data=dict(email=email))
    assert get_message("ALREADY_CONFIRMED") in response.data

    # Test if user was deleted before confirmation
    with capture_registrations() as registrations:
        data = dict(email="mary27@lp.com", password="awesome sunset", next="")
        clients.post("/register", data=data)

    user = registrations[0]["user"]
    token = registrations[0]["confirm_token"]

    with app.app_context():
        app.security.datastore.delete(user)
        app.security.datastore.commit()
        if hasattr(app.security.datastore.db, "close_db") and callable(
            app.security.datastore.db.close_db
        ):
            app.security.datastore.db.close_db(None)

    response = clients.get("/confirm/" + token, follow_redirects=True)
    assert get_message("INVALID_CONFIRMATION_TOKEN") in response.data


@pytest.mark.registerable()
def test_confirmation_template(app, client, get_message):
    # Check contents of email template - this uses a test template
    # in order to check all context vars since the default template
    # doesn't have all of them.

    recorded_tokens_sent = []

    @confirm_instructions_sent.connect_via(app)
    def on_instructions_sent(app, **kwargs):
        recorded_tokens_sent.append(kwargs["confirmation_token"])

    with capture_registrations() as registrations:
        data = dict(email="mary@lp.com", password="awesome sunset", next="")
        # Register - this will use the welcome template
        client.post("/register", data=data, follow_redirects=True)
        # Explicitly ask for confirmation -
        # this will use the confirmation_instructions template
        client.post("/confirm", data=dict(email="mary@lp.com"))
        outbox = app.mail.outbox
        assert len(outbox) == 2
        # check registration email
        matcher = re.findall(r"\w+:.*", outbox[0].body, re.IGNORECASE)
        # should be 4 - link, email, token, config item
        assert matcher[1].split(":")[1] == "mary@lp.com"
        assert matcher[2].split(":")[1] == registrations[0]["confirm_token"]
        assert matcher[2].split(":")[1] == registrations[0]["confirmation_token"]
        assert matcher[3].split(":")[1] == "True"  # register_blueprint

        # check confirmation email
        matcher = re.findall(r"\w+:.*", outbox[1].body, re.IGNORECASE)
        # should be 4 - link, email, token, config item
        assert matcher[1].split(":")[1] == "mary@lp.com"
        assert matcher[2].split(":")[1] == recorded_tokens_sent[0]
        token = matcher[2].split(":")[1]
        assert token == recorded_tokens_sent[0]
        assert matcher[3].split(":")[1] == "True"  # register_blueprint

        # check link
        _, link = matcher[0].split(":", 1)
        response = client.get(link, follow_redirects=True)
        assert get_message("EMAIL_CONFIRMED") in response.data


@pytest.mark.registerable()
@pytest.mark.settings(requires_confirmation_error_view="/confirm")
def test_requires_confirmation_error_redirect(app, clients):
    data = dict(email="jyl@lp.com", password="awesome sunset")
    response = clients.post("/register", data=data)

    response = authenticate(clients, **data, follow_redirects=True)
    assert b"send_confirmation_form" in response.data
    assert b"jyl@lp.com" in response.data


@pytest.mark.registerable()
@pytest.mark.settings(confirm_email_within="1 milliseconds")
def test_expired_confirmation_token(client, get_message):
    with capture_registrations() as registrations:
        data = dict(email="mary@lp.com", password="awesome sunset", next="")
        client.post("/register", data=data, follow_redirects=True)

    email = registrations[0]["email"]
    token = registrations[0]["confirm_token"]

    time.sleep(1)

    response = client.get("/confirm/" + token, follow_redirects=True)
    msg = get_message("CONFIRMATION_EXPIRED", within="1 milliseconds", email=email)
    assert msg in response.data


@pytest.mark.registerable()
def test_email_conflict_for_confirmation_token(
    app, client, get_message, sqlalchemy_datastore
):
    with capture_registrations() as registrations:
        data = dict(email="mary@lp.com", password="awesome sunset", next="")
        client.post("/register", data=data, follow_redirects=True)

    user = registrations[0]["user"]
    token = registrations[0]["confirm_token"]

    # Change the user's email
    user.email = "tom@lp.com"
    with app.app_context():
        sqlalchemy_datastore.put(user)
        sqlalchemy_datastore.commit()

    response = client.get("/confirm/" + token, follow_redirects=True)
    msg = get_message("INVALID_CONFIRMATION_TOKEN")
    assert msg in response.data


@pytest.mark.registerable()
@pytest.mark.settings(login_without_confirmation=True)
def test_login_when_unconfirmed(client, get_message):
    data = dict(email="mary@lp.com", password="awesome sunset", next="")
    response = client.post("/register", data=data, follow_redirects=True)
    assert b"mary@lp.com" in response.data


@pytest.mark.registerable()
def test_no_auth_token(client_nc):
    """Make sure that register doesn't return Authentication Token
    if user isn't confirmed.
    """
    response = client_nc.post(
        "/register?include_auth_token",
        json=dict(email="dude@lp.com", password="awesome sunset"),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    user = response.json["response"]["user"]
    assert len(user) == 2 and all(k in user for k in ["email", "last_update"])


@pytest.mark.registerable()
@pytest.mark.settings(login_without_confirmation=True)
def test_auth_token_unconfirmed(client_nc):
    """Make sure that register returns Authentication Token
    if user isn't confirmed, but the 'login_without_confirmation' flag is set.
    """
    response = client_nc.post(
        "/register?include_auth_token",
        json=dict(email="dude@lp.com", password="awesome sunset"),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    user = response.json["response"]["user"]
    assert len(user) == 3 and all(
        k in user for k in ["email", "last_update", "authentication_token"]
    )


@pytest.mark.registerable()
@pytest.mark.settings(login_without_confirmation=True, auto_login_after_confirm=False)
def test_confirmation_different_user_when_logged_in_no_auto(client, get_message):
    """Default - AUTO_LOGIN == false so shouldn't log in second user."""
    e1 = "dude@lp.com"
    e2 = "lady@lp.com"

    with capture_registrations() as registrations:
        for e in e1, e2:
            data = dict(email=e, password="awesome sunset", next="")
            client.post("/register", data=data)
            logout(client)

    token1 = registrations[0]["confirm_token"]
    token2 = registrations[1]["confirm_token"]

    client.get("/confirm/" + token1, follow_redirects=True)
    logout(client)
    authenticate(client, email=e1)

    response = client.get("/confirm/" + token2, follow_redirects=True)
    assert get_message("EMAIL_CONFIRMED") in response.data
    # should get a login view
    assert b'<a href="/login">Login</a>' in response.data


@pytest.mark.registerable()
@pytest.mark.settings(login_without_confirmation=True)
def test_confirmation_different_user_when_logged_in(client, get_message):
    # with default no-auto-login - first user should get logged out and second
    # should be properly confirmed (but not logged in)
    e1 = "dude@lp.com"
    e2 = "lady@lp.com"

    with capture_registrations() as registrations:
        for e in e1, e2:
            data = dict(email=e, password="awesome sunset", next="")
            response = client.post("/register", data=data)
            assert is_authenticated(client, get_message)
            logout(client)

    token1 = registrations[0]["confirm_token"]
    token2 = registrations[1]["confirm_token"]

    response = client.get("/confirm/" + token1, follow_redirects=False)
    assert "/login" in response.location
    authenticate(client, email=e1, password="awesome sunset")
    assert is_authenticated(client, get_message)

    response = client.get("/confirm/" + token2, follow_redirects=True)
    assert get_message("EMAIL_CONFIRMED") in response.data

    # first user should have been logged out
    assert not is_authenticated(client, get_message)

    authenticate(client, email=e2, password="awesome sunset")
    assert is_authenticated(client, get_message)


@pytest.mark.registerable()
@pytest.mark.settings(recoverable=True)
def test_cannot_reset_password_when_email_is_not_confirmed(client, get_message):
    email = "dude@lp.com"

    data = dict(email=email, password="awesome sunset", next="")
    response = client.post("/register", data=data, follow_redirects=True)

    response = client.post("/reset", data=dict(email=email), follow_redirects=True)
    assert get_message("CONFIRMATION_REQUIRED") in response.data


@pytest.mark.registerable()
@pytest.mark.settings(auto_login_after_confirm=False)
def test_confirm_redirect(client, get_message):
    with capture_registrations() as registrations:
        data = dict(email="jane@lp.com", password="awesome sunset", next="")
        client.post("/register", data=data, follow_redirects=True)

    token = registrations[0]["confirm_token"]

    response = client.get("/confirm/" + token)
    assert "location" in response.headers
    assert "/login" in response.location

    response = client.get(response.location)
    assert get_message("EMAIL_CONFIRMED") in response.data


@pytest.mark.registerable()
@pytest.mark.settings(post_confirm_view="/post_confirm")
def test_confirm_redirect_to_post_confirm(client, get_message):
    with capture_registrations() as registrations:
        data = dict(email="john@lp.com", password="awesome sunset", next="")
        client.post("/register", data=data, follow_redirects=True)

    token = registrations[0]["confirm_token"]

    response = client.get("/confirm/" + token, follow_redirects=False)
    assert "/post_confirm" in response.location
    assert response.headers.get("Referrer-Policy", None) == "no-referrer"


@pytest.mark.registerable()
@pytest.mark.settings(
    redirect_host="localhost:8081",
    redirect_behavior="spa",
    post_confirm_view="/confirm-redirect",
    confirm_error_view="/confirm-error",
)
def test_spa_get(app, client, get_message):
    """
    Test 'single-page-application' style redirects
    This uses json only.
    """
    with capture_flashes() as flashes:
        with capture_registrations() as registrations:
            response = client.post(
                "/register",
                json=dict(email="dude@lp.com", password="awesome sunset"),
                headers={"Content-Type": "application/json"},
            )
            assert response.headers["Content-Type"] == "application/json"
        token = registrations[0]["confirm_token"]

        response = client.get("/confirm/" + token)
        assert response.status_code == 302
        split = urlsplit(response.headers["Location"])
        assert "localhost:8081" == split.netloc
        assert "/confirm-redirect" == split.path
        qparams = dict(parse_qsl(split.query))
        assert qparams["email"] == "dude@lp.com"
        assert response.headers.get("Referrer-Policy", None) == "no-referrer"

        response = client.get("/confirm/" + token)
        split = urlsplit(response.headers["Location"])
        qparams = dict(parse_qsl(split.query))
        assert response.status_code == 302
        assert "/confirm-error" in response.location
        assert "email" not in qparams
        assert get_message("ALREADY_CONFIRMED") in qparams["info"].encode("utf-8")
        assert response.headers.get("Referrer-Policy", None) == "no-referrer"

    # Arguably for json we shouldn't have any - this is buried in register_user
    # but really shouldn't be.
    assert len(flashes) == 1


@pytest.mark.registerable()
@pytest.mark.settings(
    confirm_email_within="1 milliseconds",
    redirect_host="localhost:8081",
    redirect_behavior="spa",
    confirm_error_view="/confirm-error",
)
def test_spa_get_bad_token(app, client, get_message):
    """Test expired and invalid token"""
    with capture_flashes() as flashes:
        with capture_registrations() as registrations:
            response = client.post(
                "/register",
                json=dict(email="dude@lp.com", password="awesome sunset"),
                headers={"Content-Type": "application/json"},
            )
            assert response.headers["Content-Type"] == "application/json"
        token = registrations[0]["confirm_token"]
        time.sleep(1)

        response = client.get("/confirm/" + token)
        assert response.status_code == 302
        split = urlsplit(response.headers["Location"])
        assert "localhost:8081" == split.netloc
        assert "/confirm-error" == split.path
        qparams = dict(parse_qsl(split.query))
        assert "email" not in qparams
        assert "identity" not in qparams

        msg = get_message("CONFIRMATION_EXPIRED", within="1 milliseconds")
        assert msg == qparams["error"].encode("utf-8")

        # Test mangled token
        token = (
            "WyIxNjQ2MzYiLCIxMzQ1YzBlZmVhM2VhZjYwODgwMDhhZGU2YzU0MzZjMiJd."
            "BZEw_Q.lQyo3npdPZtcJ_sNHVHP103syjM"
            "&url_id=fbb89a8328e58c181ea7d064c2987874bc54a23d"
        )
        response = client.get("/confirm/" + token)
        assert response.status_code == 302
        split = urlsplit(response.headers["Location"])
        assert "localhost:8081" == split.netloc
        assert "/confirm-error" == split.path
        qparams = dict(parse_qsl(split.query))
        assert len(qparams) == 1
        assert all(k in qparams for k in ["error"])

        msg = get_message("INVALID_CONFIRMATION_TOKEN")
        assert msg == qparams["error"].encode("utf-8")
    assert len(flashes) == 1


@pytest.mark.filterwarnings("ignore")
@pytest.mark.registerable()
@pytest.mark.settings(auto_login_after_confirm=True, post_login_view="/postlogin")
def test_auto_login(app, client, get_message):
    with capture_registrations() as registrations:
        data = dict(email="mary@lp.com", password="password", next="")
        client.post("/register", data=data, follow_redirects=True)

    assert not is_authenticated(client, get_message)

    token = registrations[0]["confirm_token"]
    response = client.get("/confirm/" + token, follow_redirects=False)
    assert "/postlogin" == response.location
    assert is_authenticated(client, get_message)


@pytest.mark.filterwarnings("ignore")
@pytest.mark.two_factor()
@pytest.mark.registerable()
@pytest.mark.settings(two_factor_required=True, auto_login_after_confirm=True)
def test_two_factor(app, client, get_message):
    """If two-factor is enabled, the confirm shouldn't login, but start the
    2-factor setup.
    """
    with capture_registrations() as registrations:
        data = dict(email="mary@lp.com", password="password", next="")
        client.post("/register", data=data, follow_redirects=True)

    assert not is_authenticated(client, get_message)

    token = registrations[0]["confirm_token"]
    response = client.get("/confirm/" + token, follow_redirects=False)
    assert "tf-setup" in response.location


@pytest.mark.filterwarnings("ignore")
@pytest.mark.two_factor()
@pytest.mark.registerable()
@pytest.mark.settings(two_factor_required=True, auto_login_after_confirm=True)
def test_two_factor_json(app, client, get_message):
    with capture_registrations() as registrations:
        data = dict(email="dude@lp.com", password="password")
        response = client.post("/register", content_type="application/json", json=data)
        assert response.headers["content-type"] == "application/json"
        assert response.json["meta"]["code"] == 200
        assert len(response.json["response"]) == 2
        assert all(k in response.json["response"] for k in ["csrf_token", "user"])

    assert not is_authenticated(client, get_message)

    token = registrations[0]["confirm_token"]
    response = client.get("/confirm/" + token, headers={"Accept": "application/json"})

    assert response.status_code == 200
    assert response.json["response"]["tf_required"]
    assert response.json["response"]["tf_state"] == "setup_from_login"


@pytest.mark.registerable()
@pytest.mark.settings(
    user_identity_attributes=[{"username": {"mapper": lambda x: x}}],
    username_enable=True,
)
def test_email_not_identity(app, client, get_message):
    # Test that can register/confirm with email even if it isn't an IDENTITY_ATTRIBUTE
    with capture_registrations() as registrations:
        data = dict(email="mary2@lp.com", username="mary", password="awesome sunset")
        response = client.post("/register", data=data, follow_redirects=True)
        assert b"mary2@lp.com" in response.data

    token = registrations[0]["confirm_token"]
    response = client.get("/confirm/" + token, headers={"Accept": "application/json"})
    assert response.status_code == 302
    assert not is_authenticated(client, get_message)

    # check that username must be unique
    data = dict(email="mary4@lp.com", username="mary", password="awesome sunset")
    response = client.post(
        "/register", data=data, headers={"Accept": "application/json"}
    )
    assert response.status_code == 400
    assert "is already associated" in response.json["response"]["errors"][0]

    # verify that email field not present
    response = client.get("/login")  # this one has a flash containing 'email confirmed'
    response = client.get("/login")
    assert b"email" not in response.data
    assert b"username" in response.data

    response = client.get("/login", headers={"Content-Type": "application/json"})
    assert response.json["response"]["identity_attributes"] == ["username"]

    # log in with username
    response = client.post(
        "/login",
        data=dict(username="mary", password="awesome sunset"),
        follow_redirects=True,
    )
    assert b"<p>Welcome mary</p>" in response.data


@pytest.mark.settings(return_generic_responses=True)
def test_generic_response(app, client, get_message):
    # Confirm matt - then an unknown email - both should get the same answer and
    # JSON should return 200
    recorded_instructions_sent = []

    @confirm_instructions_sent.connect_via(app)
    def on_instructions_sent(app, **kwargs):
        recorded_instructions_sent.append(kwargs["token"])

    response = client.post("/confirm", data=dict(email="matt@lp.com"))
    assert len(recorded_instructions_sent) == 1
    assert get_message("CONFIRMATION_REQUEST", email="matt@lp.com") in response.data
    response = client.post("/confirm", json=dict(email="matt@lp.com"))
    assert len(recorded_instructions_sent) == 2
    assert response.status_code == 200

    # actually confirm matt
    token = recorded_instructions_sent[0]
    response = client.get("/confirm/" + token, follow_redirects=True)
    assert get_message("EMAIL_CONFIRMED") in response.data

    # Try to confirm an unknown email - should get SAME message as real email.
    response = client.post("/confirm", data=dict(email="mattwho@lp.com"))
    assert len(recorded_instructions_sent) == 2
    assert get_message("CONFIRMATION_REQUEST", email="mattwho@lp.com") in response.data
    response = client.post("/confirm", json=dict(email="mattwho@lp.com"))
    assert len(recorded_instructions_sent) == 2
    assert response.status_code == 200
    assert not any(e in response.json["response"].keys() for e in ["error", "errors"])

    # Try to confirm matt again - should ALSO get same response.
    response = client.post("/confirm", json=dict(email="matt@lp.com"))
    assert len(recorded_instructions_sent) == 2
    assert response.status_code == 200


def test_generic_with_extra(app, sqlalchemy_datastore):
    # If application adds a field, make sure we properly return errors
    # even if 'RETURN_GENERIC_RESPONSES' is set.
    class MySendConfirmationForm(SendConfirmationForm):
        recaptcha = StringField("Recaptcha", validators=[Length(min=5)])

    app.config["SECURITY_RETURN_GENERIC_RESPONSES"] = True
    app.config["SECURITY_SEND_CONFIRMATION_TEMPLATE"] = "generic_confirm.html"
    app.security = Security(
        app,
        datastore=sqlalchemy_datastore,
        send_confirmation_form=MySendConfirmationForm,
    )

    populate_data(app)
    client = app.test_client()

    # Test valid user but invalid additional form field
    # We should get a form error for the extra (invalid) field, no flash
    bad_data = dict(email="joe@lp.com", recaptcha="1234")
    good_data = dict(email="joe@lp.com", recaptcha="123456")

    with capture_flashes() as flashes:
        response = client.post("/confirm", data=bad_data)
        assert b"Field must be at least 5" in response.data
    assert len(flashes) == 0
    with capture_flashes() as flashes:
        response = client.post("/confirm", data=good_data)
    assert len(flashes) == 1

    # JSON
    with capture_flashes() as flashes:
        response = client.post("/confirm", json=bad_data)
        assert response.status_code == 400
        assert (
            "Field must be at least 5"
            in response.json["response"]["field_errors"]["recaptcha"][0]
        )
    assert len(flashes) == 0
    with capture_flashes() as flashes:
        response = client.post("/confirm", json=good_data)
        assert response.status_code == 200
    assert len(flashes) == 0

    # Try bad email AND bad recaptcha
    bad_data = dict(email="joe44-lp.com", recaptcha="1234")
    with capture_flashes() as flashes:
        response = client.post("/confirm", data=bad_data)
        assert b"Field must be at least 5" in response.data
    assert len(flashes) == 0
    with capture_flashes() as flashes:
        response = client.post("/confirm", json=bad_data)
        assert response.status_code == 400
        assert (
            "Field must be at least 5"
            in response.json["response"]["field_errors"]["recaptcha"][0]
        )
        assert len(response.json["response"]["errors"]) == 1
    assert len(flashes) == 0
