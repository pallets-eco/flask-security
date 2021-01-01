"""
    test_changeable
    ~~~~~~~~~~~~~~~

    Changeable tests

    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import base64

import pytest
from flask import Flask
import jinja2

from flask_security.core import UserMixin
from flask_security.forms import _default_field_labels
from flask_security.password_util import PasswordUtil
from flask_security.signals import password_changed, user_authenticated
from flask_security.utils import localize_callback
from tests.test_utils import (
    authenticate,
    check_xlation,
    get_session,
    hash_password,
    init_app_with_options,
    json_authenticate,
    logout,
)

pytestmark = pytest.mark.changeable()


def test_changeable_flag(app, client, get_message):
    recorded = []

    @password_changed.connect_via(app)
    def on_password_changed(app, user):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        recorded.append(user)

    authenticate(client)

    # Test change view
    response = client.get("/change", follow_redirects=True)
    assert b"Change password" in response.data

    # Test wrong original password
    response = client.post(
        "/change",
        data={
            "password": "notpassword",
            "new_password": "newpassword",
            "new_password_confirm": "newpassword",
        },
        follow_redirects=True,
    )
    assert get_message("INVALID_PASSWORD") in response.data

    # Test mismatch
    response = client.post(
        "/change",
        data={
            "password": "password",
            "new_password": "newpassword",
            "new_password_confirm": "notnewpassword",
        },
        follow_redirects=True,
    )
    assert get_message("RETYPE_PASSWORD_MISMATCH") in response.data

    # Test missing password
    response = client.post(
        "/change",
        data={"password": "   ", "new_password": "", "new_password_confirm": ""},
        follow_redirects=True,
    )
    assert get_message("PASSWORD_NOT_PROVIDED") in response.data

    # Test bad password
    response = client.post(
        "/change",
        data={"password": "password", "new_password": "a", "new_password_confirm": "a"},
        follow_redirects=True,
    )
    assert get_message("PASSWORD_INVALID_LENGTH", length=8) in response.data

    # Test same as previous
    response = client.post(
        "/change",
        data={
            "password": "password",
            "new_password": "password",
            "new_password_confirm": "password",
        },
        follow_redirects=True,
    )
    assert get_message("PASSWORD_IS_THE_SAME") in response.data

    # Test successful submit sends email notification
    with app.mail.record_messages() as outbox:
        response = client.post(
            "/change",
            data={
                "password": "password",
                "new_password": "new strong password",
                "new_password_confirm": "new strong password",
            },
            follow_redirects=True,
        )

    assert get_message("PASSWORD_CHANGE") in response.data
    assert b"Home Page" in response.data
    assert len(recorded) == 1
    assert len(outbox) == 1
    assert "Your password has been changed" in outbox[0].html

    # Test leading & trailing whitespace not stripped
    response = client.post(
        "/change",
        data={
            "password": "new strong password",
            "new_password": "      new strong password      ",
            "new_password_confirm": "      new strong password      ",
        },
        follow_redirects=True,
    )
    assert get_message("PASSWORD_CHANGE") in response.data

    # Test JSON
    data = (
        '{"password": "      new strong password      ", '
        '"new_password": "new stronger password2", '
        '"new_password_confirm": "new stronger password2"}'
    )
    response = client.post(
        "/change", data=data, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/json"

    # Test JSON errors
    data = '{"password": "newpassword"}'
    response = client.post(
        "/change", data=data, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"]["new_password"] == [
        "Password not provided"
    ]


def test_change_invalidates_session(app, client):
    # Make sure that if we change our password - prior sessions are invalidated.

    # changing password effectively re-logs in user - verify the signal
    auths = []

    @user_authenticated.connect_via(app)
    def authned(myapp, user, **extra_args):
        auths.append((user.email, extra_args["authn_via"]))

    # No remember cookie since that also be reset and auto-login.
    data = dict(email="matt@lp.com", password="password", remember="")
    response = client.post("/login", data=data)
    sess = get_session(response)
    cur_user_id = sess.get("_user_id", sess.get("user_id"))

    response = client.post(
        "/change",
        data={
            "password": "password",
            "new_password": "new strong password",
            "new_password_confirm": "new strong password",
        },
        follow_redirects=True,
    )
    # First auth was the initial login above - second should be from /change
    assert auths[1][0] == "matt@lp.com"
    assert "change" in auths[1][1]

    # Should have received a new session cookie - so should still be logged in
    response = client.get("/profile", follow_redirects=True)
    assert b"Profile Page" in response.data

    # Now use old session - shouldn't work.
    with client.session_transaction() as oldsess:
        oldsess["_user_id"] = cur_user_id
        oldsess["user_id"] = cur_user_id

    # try to access protected endpoint - shouldn't work
    response = client.get("/profile")
    assert response.status_code == 302
    assert response.headers["Location"] == "http://localhost/login?next=%2Fprofile"


def test_change_updates_remember(app, client):
    # Test that on change password - remember cookie updated
    authenticate(client)

    response = client.post(
        "/change",
        data={
            "password": "password",
            "new_password": "new strong password",
            "new_password_confirm": "new strong password",
        },
        follow_redirects=True,
    )

    # Should have received a new session cookie - so should still be logged in
    response = client.get("/profile", follow_redirects=True)
    assert b"Profile Page" in response.data

    assert "remember_token" in [c.name for c in client.cookie_jar]
    client.cookie_jar.clear_session_cookies()
    response = client.get("/profile", follow_redirects=True)
    assert b"Profile Page" in response.data


def test_change_invalidates_auth_token(app, client):
    # if change password, by default that should invalidate auth tokens
    response = json_authenticate(client)
    token = response.json["response"]["user"]["authentication_token"]
    headers = {"Authentication-Token": token}
    # make sure can access restricted page
    response = client.get("/token", headers=headers)
    assert b"Token Authentication" in response.data

    response = client.post(
        "/change",
        data={
            "password": "password",
            "new_password": "new strong password",
            "new_password_confirm": "new strong password",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    # authtoken should now be invalid
    response = client.get("/token", headers=headers)
    assert response.status_code == 302
    assert response.headers["Location"] == "http://localhost/login?next=%2Ftoken"


def test_auth_uniquifier(app):
    # If add fs_token_uniquifier to user model - change password shouldn't invalidate
    # auth tokens.
    from sqlalchemy import Column, String
    from flask_sqlalchemy import SQLAlchemy
    from flask_security.models import fsqla_v2 as fsqla
    from flask_security import Security, SQLAlchemyUserDatastore

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    db = SQLAlchemy(app)

    fsqla.FsModels.set_db_info(db)

    class Role(db.Model, fsqla.FsRoleMixin):
        pass

    class User(db.Model, fsqla.FsUserMixin):
        fs_token_uniquifier = Column(String(64), unique=True, nullable=False)

    with app.app_context():
        db.create_all()

    ds = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(app, datastore=ds)

    with app.app_context():
        ds.create_user(
            email="matt@lp.com",
            password=hash_password("password"),
        )
        ds.commit()

        client = app.test_client()

        # standard login with auth token
        response = json_authenticate(client)
        token = response.json["response"]["user"]["authentication_token"]
        headers = {"Authentication-Token": token}
        # make sure can access restricted page
        response = client.get("/token", headers=headers)
        assert b"Token Authentication" in response.data

        # change password
        response = client.post(
            "/change",
            data={
                "password": "password",
                "new_password": "new strong password",
                "new_password_confirm": "new strong password",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

        # authtoken should still be valid
        response = client.get("/token", headers=headers)
        assert response.status_code == 200


def test_xlation(app, client, get_message_local):
    # Test form and email translation
    app.config["BABEL_DEFAULT_LOCALE"] = "fr_FR"
    assert check_xlation(app, "fr_FR"), "You must run python setup.py compile_catalog"

    authenticate(client)

    response = client.get("/change", follow_redirects=True)
    with app.app_context():
        # Check header
        assert (
            f'<h1>{localize_callback("Change password")}</h1>'.encode("utf-8")
            in response.data
        )
        submit = localize_callback(_default_field_labels["change_password"])
        assert f'value="{submit}"'.encode("utf-8") in response.data

    with app.mail.record_messages() as outbox:
        response = client.post(
            "/change",
            data={
                "password": "password",
                "new_password": "new strong password",
                "new_password_confirm": "new strong password",
            },
            follow_redirects=True,
        )

    with app.app_context():
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
            str(jinja2.escape(localize_callback("Your password has been changed.")))
            in outbox[0].html
        )
        assert localize_callback("Your password has been changed") in outbox[0].body


@pytest.mark.settings(change_url="/custom_change")
def test_custom_change_url(client):
    authenticate(client)
    response = client.get("/custom_change")
    assert response.status_code == 200


@pytest.mark.settings(change_password_template="custom_security/change_password.html")
def test_custom_change_template(client):
    authenticate(client)
    response = client.get("/change")
    assert b"CUSTOM CHANGE PASSWORD" in response.data


@pytest.mark.settings(send_password_change_email=False)
def test_disable_change_emails(app, client):
    with app.mail.record_messages() as outbox:
        client.post(
            "/change",
            data={
                "password": "password",
                "new_password": "newpassword",
                "new_password_confirm": "newpassword",
            },
            follow_redirects=True,
        )
    assert len(outbox) == 0


@pytest.mark.settings(post_change_view="/profile")
def test_custom_post_change_view(client):
    authenticate(client)
    response = client.post(
        "/change",
        data={
            "password": "password",
            "new_password": "new strong password",
            "new_password_confirm": "new strong password",
        },
        follow_redirects=True,
    )

    assert b"Profile Page" in response.data


def test_token_change(app, client_nc):
    # Verify can change password using token auth only
    login_response = json_authenticate(client_nc)
    token = login_response.json["response"]["user"]["authentication_token"]

    data = dict(
        password="password",
        new_password="new strong password",
        new_password_confirm="new strong password",
    )
    response = client_nc.post(
        "/change?include_auth_token=1",
        json=data,
        headers={"Content-Type": "application/json", "Authentication-Token": token},
    )
    assert response.status_code == 200
    assert "authentication_token" in response.json["response"]["user"]


@pytest.mark.settings(api_enabled_methods=["basic"])
def test_basic_change(app, client_nc, get_message):
    # Verify can change password using basic auth
    data = dict(
        password="password",
        new_password="new strong password",
        new_password_confirm="new strong password",
    )
    response = client_nc.post("/change", data=data)
    assert b"You are not authenticated" in response.data
    assert "WWW-Authenticate" in response.headers

    response = client_nc.post(
        "/change",
        data=data,
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"matt@lp.com:password").decode("utf-8")
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    # No session so no flashing
    assert b"Home Page" in response.data


@pytest.mark.settings(password_complexity_checker="zxcvbn")
def test_easy_password(app, client):
    authenticate(client)

    data = (
        '{"password": "password", '
        '"new_password": "mattmatt2", '
        '"new_password_confirm": "mattmatt2"}'
    )
    response = client.post(
        "/change", data=data, headers={"Content-Type": "application/json"}
    )
    assert response.headers["Content-Type"] == "application/json"
    assert response.status_code == 400
    # Response from zxcvbn
    assert "Repeats like" in response.json["response"]["errors"]["new_password"][0]


def test_my_validator(app, sqlalchemy_datastore):
    class MyPwUtil(PasswordUtil):
        def validate(self, password, is_register, **kwargs):
            user = kwargs["user"]
            # This is setup in createusers for matt.
            assert user.security_number == 123456
            return ["Are you crazy?"], password

    init_app_with_options(
        app, sqlalchemy_datastore, **{"security_args": {"password_util_cls": MyPwUtil}}
    )
    client = app.test_client()

    authenticate(client)

    data = (
        '{"password": "password", '
        '"new_password": "mattmatt2", '
        '"new_password_confirm": "mattmatt2"}'
    )
    response = client.post(
        "/change", data=data, headers={"Content-Type": "application/json"}
    )
    assert response.headers["Content-Type"] == "application/json"
    assert response.status_code == 400
    assert "Are you crazy" in response.json["response"]["errors"]["new_password"][0]


@pytest.mark.settings(password_length_min=12)
def test_override_length(app, client, get_message):
    authenticate(client)
    response = client.post(
        "/change",
        data={
            "password": "password",
            "new_password": "01234567890",
            "new_password_confirm": "01234567890",
        },
        follow_redirects=True,
    )
    assert get_message("PASSWORD_INVALID_LENGTH", length=12) in response.data


def test_unicode_length(app, client, get_message):
    # From NIST and OWASP - each unicode code point should count as a character.
    authenticate(client)

    # Emoji's are 4 bytes in utf-8
    data = dict(
        password="password",
        new_password="\N{CYCLONE}\N{SUNRISE}\N{FOGGY}"
        "\N{VOLCANO}\N{CRESCENT MOON}\N{MILKY WAY}"
        "\N{FOG}\N{THERMOMETER}\N{ROSE}",
        new_password_confirm="\N{CYCLONE}\N{SUNRISE}\N{FOGGY}"
        "\N{VOLCANO}\N{CRESCENT MOON}\N{MILKY WAY}"
        "\N{FOG}\N{THERMOMETER}\N{ROSE}",
    )
    response = client.post(
        "/change", json=data, headers={"Content-Type": "application/json"}
    )
    assert response.headers["Content-Type"] == "application/json"
    assert response.status_code == 200


def test_unicode_invalid_length(app, client, get_message):
    # From NIST and OWASP - each unicode code point should count as a character.
    authenticate(client)

    # Emoji's are 4 bytes in utf-8
    data = dict(
        password="password",
        new_password="\N{CYCLONE}\N{CYCLONE}\N{FOGGY}\N{FOGGY}",
        new_password_confirm="\N{CYCLONE}\N{CYCLONE}\N{FOGGY}\N{FOGGY}",
    )
    response = client.post(
        "/change", json=data, headers={"Content-Type": "application/json"}
    )
    assert response.headers["Content-Type"] == "application/json"
    assert response.status_code == 400
    assert get_message("PASSWORD_INVALID_LENGTH", length=8) in response.data


def test_pwd_normalize(app, client):
    """ Verify that can log in with both original and normalized pwd """
    authenticate(client)

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

    # use original typed-in pwd
    response = client.post(
        "/login",
        json=dict(
            email="matt@lp.com", password="new strong password\N{ROMAN NUMERAL ONE}"
        ),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    logout(client)

    # try with normalized password
    response = client.post(
        "/login",
        json=dict(
            email="matt@lp.com",
            password="new strong password\N{LATIN CAPITAL LETTER I}",
        ),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200

    # Verify can change password using original password
    data = dict(
        password="new strong password\N{ROMAN NUMERAL ONE}",
        new_password="new strong password\N{ROMAN NUMERAL TWO}",
        new_password_confirm="new strong password\N{ROMAN NUMERAL TWO}",
    )
    response = client.post(
        "/change",
        json=data,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200


@pytest.mark.settings(password_normalize_form=None)
def test_pwd_no_normalize(app, client):
    """Verify that can log in with original but not normalized if have
    disabled normalization
    """
    authenticate(client)

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

    # try with normalized password - should fail
    response = client.post(
        "/login",
        json=dict(
            email="matt@lp.com",
            password="new strong password\N{LATIN CAPITAL LETTER I}",
        ),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400

    # use original typed-in pwd
    response = client.post(
        "/login",
        json=dict(
            email="matt@lp.com", password="new strong password\N{ROMAN NUMERAL ONE}"
        ),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200

    # Verify can change password using original password
    data = dict(
        password="new strong password\N{ROMAN NUMERAL ONE}",
        new_password="new strong password\N{ROMAN NUMERAL TWO}",
        new_password_confirm="new strong password\N{ROMAN NUMERAL TWO}",
    )
    response = client.post(
        "/change",
        json=data,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
