"""
    test_confirmable
    ~~~~~~~~~~~~~~~~

    Confirmable tests
"""

import time
from urllib.parse import parse_qsl, urlsplit

import pytest
from flask import Flask

from flask_security.core import UserMixin
from flask_security.confirmable import generate_confirmation_token
from flask_security.signals import confirm_instructions_sent, user_confirmed

from tests.test_utils import (
    authenticate,
    capture_flashes,
    capture_registrations,
    logout,
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
    def on_instructions_sent(app, user, token):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        assert isinstance(token, str)
        recorded_instructions_sent.append(user)

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
    assert "user" in response.json["response"]
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
    response = clients.get("/confirm/" + token, follow_redirects=True)
    assert get_message("EMAIL_CONFIRMED") in response.data
    assert len(recorded_confirms) == 1

    # Test already confirmed
    response = clients.get("/confirm/" + token, follow_redirects=True)
    assert get_message("ALREADY_CONFIRMED") in response.data
    assert len(recorded_instructions_sent) == 2

    # Test already confirmed and expired token
    app.config["SECURITY_CONFIRM_EMAIL_WITHIN"] = "-1 days"
    with app.app_context():
        user = registrations[0]["user"]
        expired_token = generate_confirmation_token(user)
    response = clients.get("/confirm/" + expired_token, follow_redirects=True)
    assert get_message("ALREADY_CONFIRMED") in response.data
    assert len(recorded_instructions_sent) == 2

    # Test already confirmed when asking for confirmation instructions
    logout(clients)

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
        if hasattr(app.security.datastore.db, "close_db"):
            app.security.datastore.db.close_db(None)

    response = clients.get("/confirm/" + token, follow_redirects=True)
    assert get_message("INVALID_CONFIRMATION_TOKEN") in response.data


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

    user = registrations[0]["user"]
    token = registrations[0]["confirm_token"]

    time.sleep(1)

    response = client.get("/confirm/" + token, follow_redirects=True)
    msg = get_message("CONFIRMATION_EXPIRED", within="1 milliseconds", email=user.email)
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
    """ Default - AUTO_LOGIN == false so shouldn't log in second user. """
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
    assert (
        b'<input id="password" name="password" required type="password" value="">'
        in response.data
    )


@pytest.mark.registerable()
@pytest.mark.settings(login_without_confirmation=True)
def test_confirmation_different_user_when_logged_in(client, get_message):
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
    assert b"Welcome lady@lp.com" in response.data


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

    response = client.get("/confirm/" + token, follow_redirects=True)
    assert b"Post Confirm" in response.data


@pytest.mark.registerable()
@pytest.mark.settings(
    redirect_host="localhost:8081",
    redirect_behavior="spa",
    post_confirm_view="/confirm-redirect",
)
def test_spa_get(app, client):
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
    """ Test expired and invalid token"""
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
        assert all(k in qparams for k in ["email", "error", "identity"])
        assert qparams["identity"] == "dude@lp.com"

        msg = get_message(
            "CONFIRMATION_EXPIRED", within="1 milliseconds", email="dude@lp.com"
        )
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


@pytest.mark.two_factor()
@pytest.mark.registerable()
@pytest.mark.settings(two_factor_required=True)
def test_two_factor(app, client):
    """If two-factor is enabled, the confirm shouldn't login, but start the
    2-factor setup.
    """
    with capture_registrations() as registrations:
        data = dict(email="mary@lp.com", password="password", next="")
        client.post("/register", data=data, follow_redirects=True)

    # make sure not logged in
    response = client.get("/profile")
    assert response.status_code == 302
    assert "/login?next=%2Fprofile" in response.location

    token = registrations[0]["confirm_token"]
    response = client.get("/confirm/" + token, follow_redirects=False)
    assert "tf-setup" in response.location


@pytest.mark.two_factor()
@pytest.mark.registerable()
@pytest.mark.settings(two_factor_required=True)
def test_two_factor_json(app, client, get_message):
    with capture_registrations() as registrations:
        data = dict(email="dude@lp.com", password="password")
        response = client.post("/register", content_type="application/json", json=data)
        assert response.headers["content-type"] == "application/json"
        assert response.json["meta"]["code"] == 200
        assert len(response.json["response"]) == 2
        assert all(k in response.json["response"] for k in ["csrf_token", "user"])

    # make sure not logged in
    response = client.get("/profile", headers={"accept": "application/json"})
    assert response.status_code == 401
    assert response.json["response"]["error"].encode("utf-8") == get_message(
        "UNAUTHENTICATED"
    )

    token = registrations[0]["confirm_token"]
    response = client.get("/confirm/" + token, headers={"Accept": "application/json"})

    assert response.status_code == 200
    assert response.json["response"]["tf_required"]
    assert response.json["response"]["tf_state"] == "setup_from_login"


@pytest.mark.registerable()
@pytest.mark.settings(
    user_identity_attributes=[{"username": {"mapper": lambda x: x}}],
)
def test_email_not_identity(app, sqlalchemy_datastore, get_message):
    # Test that can register/confirm with email even if it isn't an IDENTITY_ATTRIBUTE
    from flask_security import ConfirmRegisterForm, Security, unique_identity_attribute
    from wtforms import StringField, validators

    class MyRegisterForm(ConfirmRegisterForm):
        username = StringField(
            "Username",
            validators=[validators.data_required(), unique_identity_attribute],
        )

    app.config["SECURITY_CONFIRM_REGISTER_FORM"] = MyRegisterForm
    security = Security(datastore=sqlalchemy_datastore)
    security.init_app(app)

    client = app.test_client()

    with capture_registrations() as registrations:
        data = dict(email="mary2@lp.com", username="mary", password="awesome sunset")
        response = client.post("/register", data=data, follow_redirects=True)
        assert b"mary2@lp.com" in response.data

    token = registrations[0]["confirm_token"]
    response = client.get("/confirm/" + token, headers={"Accept": "application/json"})
    assert response.status_code == 302
    assert response.location == "http://localhost/"

    logout(client)

    # check that username must be unique
    data = dict(email="mary4@lp.com", username="mary", password="awesome sunset")
    response = client.post(
        "/register", data=data, headers={"Accept": "application/json"}
    )
    assert response.status_code == 400
    assert "is already associated" in response.json["response"]["errors"]["username"][0]

    # log in with username - this uses the age-old hack that although the form's
    # input label says "email" - it in fact will accept any identity attribute.
    response = client.post(
        "/login",
        data=dict(email="mary", password="awesome sunset"),
        follow_redirects=True,
    )
    assert b"<p>Welcome mary</p>" in response.data
