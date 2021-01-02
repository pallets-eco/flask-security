"""
    test_csrf
    ~~~~~~~~~~~~~~~~~

    CSRF tests

    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""
from contextlib import contextmanager
import time

import flask_wtf.csrf

import pytest
from flask_wtf import CSRFProtect

from tests.test_utils import get_session, logout


REAL_VALIDATE_CSRF = None


@contextmanager
def mp_validate_csrf():
    """ Make sure we are really calling CSRF validation and getting correct answer """
    orig_validate_csrf = flask_wtf.csrf.validate_csrf
    try:
        mp = MpValidateCsrf(orig_validate_csrf)
        flask_wtf.csrf.validate_csrf = mp.mp_validate_csrf
        yield mp
    finally:
        flask_wtf.csrf.validate_csrf = orig_validate_csrf


class MpValidateCsrf:
    success = 0
    failure = 0

    def __init__(self, real_validate_csrf):
        MpValidateCsrf.success = 0
        MpValidateCsrf.failure = 0
        global REAL_VALIDATE_CSRF
        REAL_VALIDATE_CSRF = real_validate_csrf

    @staticmethod
    def mp_validate_csrf(data, secret_key=None, time_limit=None, token_key=None):

        try:
            REAL_VALIDATE_CSRF(data, secret_key, time_limit, token_key)
            MpValidateCsrf.success += 1
        except Exception:
            MpValidateCsrf.failure += 1
            raise


def _get_csrf_token(client):
    response = client.get(
        "/login", data={}, headers={"Content-Type": "application/json"}
    )
    return response.json["response"]["csrf_token"]


def json_login(
    client,
    email="matt@lp.com",
    password="password",
    endpoint=None,
    use_header=False,
    remember=None,
):
    """Return tuple (auth_token, csrf_token)
    Note that since this is sent as JSON rather than form that csrfProtect
    won't find token value (since it looks in request.form).
    """
    csrf_token = _get_csrf_token(client)
    data = dict(email=email, password=password, remember=remember)

    if use_header:
        headers = {"X-CSRF-Token": csrf_token}
    else:
        headers = {}
        data["csrf_token"] = csrf_token

    response = client.post(
        endpoint or "/login?include_auth_token",
        content_type="application/json",
        json=data,
        headers=headers,
    )
    assert response.status_code == 200
    rd = response.json["response"]
    return rd["user"]["authentication_token"], rd["csrf_token"]


def json_logout(client):
    response = client.post("logout", content_type="application/json", data={})
    assert response.status_code == 200
    assert response.json["meta"]["code"] == 200
    return response


def test_login_csrf(app, client):
    app.config["WTF_CSRF_ENABLED"] = True

    # This shouldn't log in - but return login form with csrf token.
    data = dict(email="matt@lp.com", password="password", remember="y")
    response = client.post("/login", data=data)
    assert response.status_code == 200
    assert b"csrf_token" in response.data

    data["csrf_token"] = _get_csrf_token(client)
    response = client.post("/login", data=data, follow_redirects=True)
    assert response.status_code == 200
    assert b"Welcome matt" in response.data

    response = logout(client, follow_redirects=True)
    assert response.status_code == 200
    assert b"Log in" in response.data


def test_login_csrf_double(app, client):
    # Test if POST login while already logged in - just redirects to POST_LOGIN
    app.config["WTF_CSRF_ENABLED"] = True

    # This shouldn't log in - but return login form with csrf token.
    data = dict(email="matt@lp.com", password="password", remember="y")
    response = client.post("/login", data=data)
    assert response.status_code == 200
    assert b"csrf_token" in response.data

    data["csrf_token"] = _get_csrf_token(client)
    response = client.post("/login", data=data, follow_redirects=True)
    assert response.status_code == 200
    assert b"Welcome matt" in response.data

    data["csrf_token"] = _get_csrf_token(client)
    # Note - should redirect to POST_LOGIN with current user ignoring form data.
    data["email"] = "newguy@me.com"
    response = client.post("/login", data=data, follow_redirects=True)
    assert response.status_code == 200
    assert b"Welcome matt" in response.data


def test_login_csrf_json(app, client):
    app.config["WTF_CSRF_ENABLED"] = True

    with mp_validate_csrf() as mp:
        auth_token, csrf_token = json_login(client)
        assert auth_token
        assert csrf_token
    # Should be just one call to validate - since CSRFProtect not enabled.
    assert mp.success == 1 and mp.failure == 0

    response = json_logout(client)
    session = get_session(response)
    assert "csrf_token" not in session


def test_login_csrf_json_header(app, client):
    app.config["WTF_CSRF_ENABLED"] = True
    CSRFProtect(app)

    with mp_validate_csrf() as mp:
        auth_token, csrf_token = json_login(client, use_header=True)
        assert auth_token
        assert csrf_token
    assert mp.success == 2 and mp.failure == 0
    json_logout(client)


@pytest.mark.settings(csrf_ignore_unauth_endpoints=True)
def test_login_csrf_unauth_ok(app, client):
    app.config["WTF_CSRF_ENABLED"] = True

    with mp_validate_csrf() as mp:
        # This should log in.
        data = dict(email="matt@lp.com", password="password", remember="y")
        response = client.post("/login", data=data, follow_redirects=True)
        assert response.status_code == 200
        assert b"Welcome matt" in response.data
    assert mp.success == 0 and mp.failure == 0
    logout(client)


@pytest.mark.settings(csrf_ignore_unauth_endpoints=True)
def test_login_csrf_unauth_double(app, client, get_message):
    # Test double login w/o CSRF returns unauth required error message.
    app.config["WTF_CSRF_ENABLED"] = True

    # This should log in.
    data = dict(email="matt@lp.com", password="password", remember="y")
    response = client.post("/login", data=data, follow_redirects=True)
    assert response.status_code == 200
    assert b"Welcome matt" in response.data

    # login in again - should work
    response = client.post("/login", content_type="application/json", json=data)
    assert response.status_code == 400
    assert response.json["response"]["error"].encode("utf-8") == get_message(
        "ANONYMOUS_USER_REQUIRED"
    )


@pytest.mark.recoverable()
def test_reset(app, client):
    """ Test that form-based CSRF works for /reset """
    app.config["WTF_CSRF_ENABLED"] = True

    with mp_validate_csrf() as mp:
        data = dict(email="matt@lp.com")
        # should fail - no CSRF token
        response = client.post("/reset", content_type="application/json", json=data)
        assert response.status_code == 400

        data["csrf_token"] = _get_csrf_token(client)
        response = client.post("/reset", content_type="application/json", json=data)
        assert response.status_code == 200
    assert mp.success == 1 and mp.failure == 1


@pytest.mark.recoverable()
def test_cp_reset(app, client):
    """Test that header based CSRF works for /reset when
    using WTF_CSRF_CHECK_DEFAULT=False.
    """
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    CSRFProtect(app)

    with mp_validate_csrf() as mp:
        data = dict(email="matt@lp.com")
        # should fail - no CSRF token
        response = client.post("/reset", content_type="application/json", json=data)
        assert response.status_code == 400

        csrf_token = _get_csrf_token(client)
        response = client.post(
            "/reset",
            content_type="application/json",
            json=data,
            headers={"X-CSRF-Token": csrf_token},
        )
        assert response.status_code == 200
    # 2 failures since the first time it will check twice - once due to @unauth_csrf
    # which will fall-through on error to form validation (which also fails).
    assert mp.success == 1 and mp.failure == 2


@pytest.mark.changeable()
def test_cp_with_token(app, client):
    # Make sure can use returned CSRF-Token in Header.
    app.config["WTF_CSRF_ENABLED"] = True
    CSRFProtect(app)

    auth_token, csrf_token = json_login(client, use_header=True)

    # make sure returned csrf_token works in header.
    data = dict(
        password="password",
        new_password="battery staple",
        new_password_confirm="battery staple",
    )

    with mp_validate_csrf() as mp:
        response = client.post(
            "/change",
            content_type="application/json",
            json=data,
            headers={"X-CSRF-Token": csrf_token},
        )
        assert response.status_code == 200
    assert mp.success == 1 and mp.failure == 0
    json_logout(client)


def test_cp_login_json_no_session(app, client_nc):
    # Test with global CSRFProtect on and not sending cookie - nothing works.
    app.config["WTF_CSRF_ENABLED"] = True
    CSRFProtect(app)

    # This shouldn't log in - and will return 400
    with mp_validate_csrf() as mp:

        data = dict(email="matt@lp.com", password="password", remember="y")
        response = client_nc.post(
            "/login",
            content_type="application/json",
            json=data,
            headers={"Accept": "application/json"},
        )
        assert response.status_code == 400

        # This still wont work since we don't send a session cookie
        response = client_nc.post(
            "/login",
            content_type="application/json",
            json=data,
            headers={"X-CSRF-Token": _get_csrf_token(client_nc)},
        )
        assert response.status_code == 400

    # Although failed - CSRF should have been called
    assert mp.failure == 2


@pytest.mark.settings(CSRF_PROTECT_MECHANISMS=["basic", "session"])
def test_cp_config(app, client):
    # Test improper config (must have WTF_CSRF_CHECK_DEFAULT false if setting
    # CSRF_PROTECT_MECHANISMS
    app.config["WTF_CSRF_ENABLED"] = True
    CSRFProtect(app)

    # The check is done on first request.
    with pytest.raises(ValueError) as ev:
        logout(client)
    assert "must be set to False" in str(ev.value)


@pytest.mark.settings(CSRF_PROTECT_MECHANISMS=["basic", "session"])
def test_cp_config2(app, client):
    # Test improper config (must have CSRFProtect configured if setting
    # CSRF_PROTECT_MECHANISMS
    app.config["WTF_CSRF_ENABLED"] = True

    # The check is done on first request.
    with pytest.raises(ValueError) as ev:
        logout(client)
    assert "CsrfProtect not part of application" in str(ev.value)


@pytest.mark.changeable()
@pytest.mark.settings(CSRF_PROTECT_MECHANISMS=["basic", "session"])
def test_different_mechanisms(app, client):
    # Verify that using token doesn't require CSRF, but sessions do
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    CSRFProtect(app)

    with mp_validate_csrf() as mp:
        auth_token, csrf_token = json_login(client)

        # session based change password should fail
        data = dict(
            password="password",
            new_password="battery staple",
            new_password_confirm="battery staple",
        )

        response = client.post(
            "/change", json=data, headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 400
        assert b"The CSRF token is missing" in response.data

        # token based should work
        response = client.post(
            "/change",
            json=data,
            headers={
                "Content-Type": "application/json",
                "Authentication-Token": auth_token,
            },
        )
        assert response.status_code == 200
    assert mp.success == 1 and mp.failure == 2


@pytest.mark.changeable()
@pytest.mark.settings(
    CSRF_PROTECT_MECHANISMS=["basic", "session"], csrf_ignore_unauth_endpoints=True
)
def test_different_mechanisms_nc(app, client_nc):
    # Verify that using token and no session cookie works
    # Note that we had to disable unauth_endpoints since you can't log in
    # w/ CSRF if you don't send in the session cookie.
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    CSRFProtect(app)

    with mp_validate_csrf() as mp:
        auth_token, csrf_token = json_login(client_nc)

        # token based should work
        data = dict(
            password="password",
            new_password="battery staple",
            new_password_confirm="battery staple",
        )
        response = client_nc.post(
            "/change",
            json=data,
            headers={
                "Content-Type": "application/json",
                "Authentication-Token": auth_token,
            },
        )
        assert response.status_code == 200
    assert mp.success == 0 and mp.failure == 0


@pytest.mark.settings(
    csrf_ignore_unauth_endpoints=True, CSRF_COOKIE={"key": "X-XSRF-Token"}
)
def test_csrf_cookie(app, client):
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    CSRFProtect(app)

    json_login(client)
    found = False
    for cookie in client.cookie_jar:
        if cookie.name == "X-XSRF-Token":
            found = True
            assert cookie.path == "/"
    assert found

    # Make sure cleared on logout
    response = client.post("/logout", content_type="application/json")
    assert response.status_code == 200
    assert "X-XSRF-Token" not in [c.name for c in client.cookie_jar]


@pytest.mark.settings(CSRF_COOKIE={"key": "X-XSRF-Token"})
@pytest.mark.changeable()
def test_cp_with_token_cookie(app, client):
    # Make sure can use returned CSRF-Token cookie in Header when changing password.
    app.config["WTF_CSRF_ENABLED"] = True
    CSRFProtect(app)

    json_login(client, use_header=True)

    # make sure returned csrf_token works in header.
    data = dict(
        password="password",
        new_password="battery staple",
        new_password_confirm="battery staple",
    )
    csrf_token = [c.value for c in client.cookie_jar if c.name == "X-XSRF-Token"][0]
    with mp_validate_csrf() as mp:
        response = client.post(
            "/change",
            content_type="application/json",
            json=data,
            headers={"X-XSRF-Token": csrf_token},
        )
        assert response.status_code == 200
    assert mp.success == 1 and mp.failure == 0
    json_logout(client)
    assert "X-XSRF-Token" not in [c.name for c in client.cookie_jar]


@pytest.mark.settings(
    CSRF_COOKIE={"key": "X-XSRF-Token"}, csrf_ignore_unauth_endpoints=True
)
@pytest.mark.changeable()
def test_cp_with_token_cookie_expire(app, client):
    # Make sure that we get a new Csrf-Token cookie if expired.
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["WTF_CSRF_TIME_LIMIT"] = 1
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    CSRFProtect(app)

    json_login(client, use_header=True)

    # sleep so make csrf_token expires
    time.sleep(2)
    data = dict(
        password="password",
        new_password="battery staple",
        new_password_confirm="battery staple",
    )
    csrf_token = [c.value for c in client.cookie_jar if c.name == "X-XSRF-Token"][0]
    with mp_validate_csrf() as mp:
        response = client.post(
            "/change",
            content_type="application/json",
            json=data,
            headers={"X-XSRF-Token": csrf_token},
        )
        assert response.status_code == 400
        assert b"expired" in response.data

        # Should have gotten a new CSRF cookie value
        new_csrf_token = [
            c.value for c in client.cookie_jar if c.name == "X-XSRF-Token"
        ][0]
        assert csrf_token != new_csrf_token
    # 2 failures since the utils:csrf_cookie_handler will check
    assert mp.success == 0 and mp.failure == 2
    json_logout(client)
    assert "X-XSRF-Token" not in [c.name for c in client.cookie_jar]


@pytest.mark.settings(
    CSRF_COOKIE={"key": "X-XSRF-Token"}, CSRF_COOKIE_REFRESH_EACH_REQUEST=True
)
@pytest.mark.changeable()
def test_cp_with_token_cookie_refresh(app, client):
    # Test CSRF_COOKIE_REFRESH_EACH_REQUEST
    app.config["WTF_CSRF_ENABLED"] = True
    CSRFProtect(app)

    json_login(client, use_header=True)

    # make sure returned csrf_token works in header.
    data = dict(
        password="password",
        new_password="battery staple",
        new_password_confirm="battery staple",
    )

    csrf_cookie = [c for c in client.cookie_jar if c.name == "X-XSRF-Token"][0]
    with mp_validate_csrf() as mp:
        # Delete cookie - we should always get a new one
        client.delete_cookie(csrf_cookie.domain, csrf_cookie.name)
        response = client.post(
            "/change",
            content_type="application/json",
            json=data,
            headers={"X-XSRF-Token": csrf_cookie.value},
        )
        assert response.status_code == 200
        csrf_cookie = [c for c in client.cookie_jar if c.name == "X-XSRF-Token"][0]
        assert csrf_cookie
    assert mp.success == 1 and mp.failure == 0

    # delete cookie again, do a 'GET' - the REFRESH_COOKIE_ON_EACH_REQUEST should
    # send us a new one
    client.delete_cookie(csrf_cookie.domain, csrf_cookie.name)
    response = client.get("/change")
    assert response.status_code == 200
    csrf_cookie = [c for c in client.cookie_jar if c.name == "X-XSRF-Token"][0]
    assert csrf_cookie

    json_logout(client)
    assert "X-XSRF-Token" not in [c.name for c in client.cookie_jar]


@pytest.mark.settings(CSRF_COOKIE={"key": "X-XSRF-Token"})
@pytest.mark.changeable()
def test_remember_login_csrf_cookie(app, client):
    # Test csrf cookie upon resuming a remember session
    app.config["WTF_CSRF_ENABLED"] = True
    CSRFProtect(app)

    # Login with remember_token generation
    json_login(client, use_header=True, remember=True)

    csrf_cookie = [c for c in client.cookie_jar if c.name == "X-XSRF-Token"][0]
    session_cookie = [c for c in client.cookie_jar if c.name == "session"][0]
    # Delete session and csrf cookie - we should always get new ones
    client.delete_cookie(csrf_cookie.domain, csrf_cookie.name)
    client.delete_cookie(session_cookie.domain, session_cookie.name)

    # Do a simple get request with the remember_token cookie present
    assert "remember_token" in [c.name for c in client.cookie_jar]
    response = client.get("/profile")
    assert response.status_code == 200
    assert "session" in [c.name for c in client.cookie_jar]
    assert "X-XSRF-Token" in [c.name for c in client.cookie_jar]
    # Logout and check that everything cleans up nicely
    json_logout(client)
    assert "remember_token" not in [c.name for c in client.cookie_jar]
    assert "session" not in [c.name for c in client.cookie_jar]
    assert "X-XSRF-Token" not in [c.name for c in client.cookie_jar]
