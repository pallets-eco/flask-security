"""
test_change_username
~~~~~~~~~~~~~~~~~~~~

Change username tests

:copyright: (c) 2025-2025 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.
"""

import pytest
from flask import Flask
import markupsafe

from flask_security import UsernameUtil, UserMixin, username_changed
from flask_security.forms import _default_field_labels
from flask_security.utils import localize_callback
from tests.test_utils import (
    authenticate,
    check_location,
    check_xlation,
    get_form_input_value,
    init_app_with_options,
    is_authenticated,
    logout,
)

pytestmark = pytest.mark.change_username()


@pytest.mark.settings(
    post_change_username_view="/post_change_username", username_enable=True
)
def test_cu(app, clients, get_message):
    recorded = []

    @username_changed.connect_via(app)
    def on_username_changed(app, user, old_username):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        recorded.append((user, old_username))

    authenticate(clients)

    # Test change view
    response = clients.get("/change-username", follow_redirects=True)
    assert b"Change Username" in response.data

    # test length validation
    response = clients.post(
        "/change-username",
        data={"username": "me"},
        follow_redirects=True,
    )
    assert get_message("USERNAME_INVALID_LENGTH", min=4, max=32) in response.data

    # Test successful submit sends email notification
    response = clients.post(
        "/change-username",
        data={"username": "memynewusername"},
        follow_redirects=True,
    )
    outbox = app.mail.outbox

    assert get_message("USERNAME_CHANGE") in response.data
    assert b"Post Change Username" in response.data
    assert len(recorded) == 1
    assert len(outbox) == 1
    assert "Your username has been changed" in outbox[0].body
    response = clients.get("/change-username", follow_redirects=True)
    assert b"memynewusername" in response.data

    # authenticate with new username
    logout(clients)
    clients.post("/login", data=dict(username="memynewusername", password="password"))
    assert is_authenticated(clients, get_message)

    # Test same as previous
    response = clients.post(
        "/change-username",
        data={"username": "memynewusername"},
        follow_redirects=True,
    )
    assert (
        get_message("USERNAME_ALREADY_ASSOCIATED", username="memynewusername")
        in response.data
    )

    # since username isn't required - change it to nothing
    response = clients.post(
        "/change-username",
        data={"username": ""},
        follow_redirects=True,
    )
    outbox = app.mail.outbox

    assert get_message("USERNAME_CHANGE") in response.data
    assert b"Post Change Username" in response.data
    assert len(recorded) == 2
    assert len(outbox) == 2
    assert "Your username has been changed" in outbox[1].body

    # shouldn't be able to log in with username
    logout(clients)
    clients.post("/login", data=dict(username="memynewusername", password="password"))
    assert not is_authenticated(clients, get_message)


@pytest.mark.settings(
    post_change_username_view="/post_change_username", username_enable=True
)
def test_cu_json(app, clients, get_message):
    # Test JSON
    recorded = []

    @username_changed.connect_via(app)
    def on_username_changed(app, user, old_username):
        recorded.append((user, old_username))

    response = clients.get("/change-username", content_type="application/json")
    assert response.status_code == 401

    authenticate(clients)
    response = clients.get("/change-username", content_type="application/json")
    assert response.json["response"]["current_username"] == "matt"

    response = clients.post("/change-username", json={"username": "memyjsonusername"})
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/json"
    assert len(recorded) == 1
    user, old = recorded[0]
    assert old == "matt"

    # Test JSON errors
    response = clients.post("/change-username", json={"username": "my"})
    assert response.status_code == 400
    assert response.json["response"]["field_errors"]["username"] == [
        "Username must be at least 4 characters and less than 32 characters"
    ]

    # authenticate with old username
    logout(clients)
    clients.post("/login", json=dict(username="matt", password="password"))
    assert not is_authenticated(clients, get_message)

    # authenticate with new username
    logout(clients)
    clients.post("/login", json=dict(username="memyjsonusername", password="password"))
    assert is_authenticated(clients, get_message)


@pytest.mark.settings(username_enable=True, username_required=True)
def test_cu_required(app, client, get_message):
    client.post("/login", json=dict(username="matt", password="password"))

    response = client.post("/change-username", json={"username": ""})
    assert (
        get_message("USERNAME_NOT_PROVIDED")
        == response.json["response"]["field_errors"]["username"][0].encode()
    )


@pytest.mark.app_settings(babel_default_locale="fr_FR")
@pytest.mark.babel()
def test_xlation(app, client, get_message_local):
    pytest.skip()
    # Test form and email translation
    assert check_xlation(app, "fr_FR"), "You must run python setup.py compile_catalog"

    authenticate(client)

    response = client.get("/change", follow_redirects=True)
    with app.test_request_context():
        # Check header
        assert (
            f'<h1>{localize_callback("Change password")}</h1>'.encode() in response.data
        )
        submit = localize_callback(_default_field_labels["change_password"])
        assert f'value="{submit}"'.encode() in response.data

    response = client.post(
        "/change",
        data={
            "password": "password",
            "new_password": "new strong password",
            "new_password_confirm": "new strong password",
        },
        follow_redirects=True,
    )
    outbox = app.mail.outbox

    with app.test_request_context():
        assert get_message_local("PASSWORD_CHANGE").encode("utf-8") in response.data
        assert b"Home Page" in response.data
        assert len(outbox) == 1
        assert (
            localize_callback(
                app.config["SECURITY_EMAIL_SUBJECT_PASSWORD_CHANGE_NOTICE"]
            )
            in outbox[0].subject
        )
        assert (
            str(markupsafe.escape(localize_callback("Your password has been changed.")))
            in outbox[0].alternatives[0][0]
        )
        assert localize_callback("Your password has been changed") in outbox[0].body


@pytest.mark.settings(change_username_url="/custom-change-username")
def test_custom_change_url(client):
    authenticate(client)
    response = client.get("/custom-change-username")
    assert response.status_code == 200
    assert b"Change Username" in response.data


@pytest.mark.settings(change_username_template="custom_security/change_username.html")
def test_custom_change_template(client):
    authenticate(client)
    response = client.get("/change-username")
    assert b"CUSTOM CHANGE USERNAME" in response.data


@pytest.mark.settings(send_username_change_email=False)
def test_disable_change_emails(app, client):
    authenticate(client)
    response = client.post(
        "/change-username",
        json={"username": "mynewusername"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert not app.mail.outbox


@pytest.mark.settings(post_change_username_view="/profile")
def test_custom_post_change_view(client):
    authenticate(client)
    response = client.post(
        "/change-username",
        data={"username": "mynewusername"},
        follow_redirects=True,
    )

    assert b"Profile Page" in response.data


def test_my_validator(app, sqlalchemy_datastore):
    class MyUsernameUtil(UsernameUtil):
        def check_username(self, username):
            if username == "nowayjose":
                return "Are you crazy?"

    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"security_args": {"username_util_cls": MyUsernameUtil}},
    )
    tcl = app.test_client()
    authenticate(tcl)

    response = tcl.post("/change-username", json=dict(username="nowayjose"))
    assert response.status_code == 400
    assert "Are you crazy" in response.json["response"]["errors"][0]


@pytest.mark.settings(username_enable=True)
def test_username_normalize(app, client):
    """Verify that can log in with both original and normalized username"""
    authenticate(client)
    response = client.post(
        "/change-username", json=dict(username="newusername\N{ROMAN NUMERAL ONE}")
    )
    assert response.status_code == 200
    logout(client)

    # use original typed-in username
    response = client.post(
        "/login",
        json=dict(username="newusername\N{ROMAN NUMERAL ONE}", password="password"),
    )
    assert response.status_code == 200
    logout(client)

    # try with normalized username
    response = client.post(
        "/login",
        json=dict(
            username="newusername\N{LATIN CAPITAL LETTER I}",
            password="password",
        ),
    )
    assert response.status_code == 200


@pytest.mark.settings(username_normalize_form=None, username_enable=True)
def test_username_no_normalize(app, client):
    """Verify that can log in with original but not normalized if have
    disabled normalization
    """
    authenticate(client)
    response = client.post(
        "/change-username", json=dict(username="newusername\N{ROMAN NUMERAL ONE}")
    )
    assert response.status_code == 200
    logout(client)

    # try with normalized password - should fail
    response = client.post(
        "/login",
        json=dict(
            username="newusername\N{LATIN CAPITAL LETTER I}", password="password"
        ),
    )
    assert response.status_code == 400

    # use original typed-in username
    response = client.post(
        "/login",
        json=dict(username="newusername\N{ROMAN NUMERAL ONE}", password="password"),
    )
    assert response.status_code == 200


@pytest.mark.csrf(ignore_unauth=True)
@pytest.mark.settings(post_change_username_view="/post_change_username_view")
def test_csrf(app, client):
    # enable CSRF, make sure template shows CSRF errors.
    authenticate(client)
    data = {
        "username": "mynewusername",
    }
    response = client.post("/change-username", data=data)
    assert b"The CSRF token is missing" in response.data
    # Note that we get a CSRF token EVEN for errors - this seems odd
    # but can't find anything that says its a security issue
    csrf_token = get_form_input_value(response, "csrf_token")

    data["csrf_token"] = csrf_token
    response = client.post("/change-username", data=data)
    assert check_location(app, response.location, "/post_change_username_view")


@pytest.mark.csrf(ignore_unauth=True, csrfprotect=True)
def test_csrf_json(app, client):
    # This tests the handle_csrf code path - especially the JSON code path
    # that should return a JSON response!
    authenticate(client)
    response = client.post("/change-username", json=dict(username="mynewusername"))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0] == "The CSRF token is missing."

    response = client.get("/change-username", content_type="application/json")
    csrf_token = response.json["response"]["csrf_token"]
    response = client.post(
        "/change-username",
        json=dict(username="mynewusername"),
        headers={"X-CSRF-Token": csrf_token},
    )
    assert response.status_code == 200
