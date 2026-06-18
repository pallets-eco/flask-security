"""
test_tokens
~~~~~~~~~~~~~~~~

Refresh/Auth Token functionality tests

:copyright: (c) 2026-2026 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.
"""

from datetime import datetime, timedelta, timezone
import math

import pytest
from freezegun import freeze_time
from itsdangerous import SignatureExpired
from sqlalchemy import Column, String

from flask_security.datastore import PeeweeDatastore
from flask_security.tokens import RefreshTokenErrors
from flask_security.utils import parse_auth_token
from tests.test_csrf import _get_csrf_token
from tests.test_utils import (
    check_signals,
    json_authenticate,
    logout,
    FakeSerializer,
    verify_token,
)

pytestmark = pytest.mark.refresh_token()


def _set_refresh_tracker(app, refresh_token, **kwargs):
    with app.app_context():
        tdata = app.security.refresh_token_serializer.loads(refresh_token)
        refresh_tracker = app.security.datastore.find_refresh_tracker(tdata["family"])
        for k, v in kwargs.items():
            setattr(refresh_tracker, k, v)
        app.security.datastore.put(refresh_tracker)
        app.security.datastore.commit()
        if isinstance(app.security.datastore, PeeweeDatastore):
            app.security.datastore.db.close_db(None)


@pytest.mark.app_settings(testing_no_cookies=True)
@pytest.mark.settings(refresh_token_cookie_name=None)
def test_refresh(app, clients, get_message):
    """Test basic refresh token flow.
    - authenticate and receive auth_token and refresh_token
    - we hack the auth_token to be already expired
    - we should get a 401 when using it
    - use the /refresh-token endpoint to get a new refresh_token and auth_token
    - auth_token should be valid
    """
    start_ts = datetime.now(timezone.utc).replace(tzinfo=None).timestamp()
    max_age = app.config["SECURITY_REFRESH_TOKEN_MAX_AGE"]
    rts = app.security.remember_token_serializer
    app.security.remember_token_serializer = FakeSerializer(2.0)
    response = json_authenticate(clients)
    with pytest.raises(TypeError):
        clients.get_cookie("session")

    auth_token1 = response.json["response"]["user"]["authentication_token"]
    refresh_token = response.json["response"]["user"]["refresh_token"]

    tdict = app.security.refresh_token_serializer.loads(refresh_token)
    assert (
        tdict["expires_at"]
        > ((datetime.today() + max_age) - timedelta(days=1)).timestamp()
    )
    assert tdict["gen"] == 1
    assert tdict["last_used_at"] >= start_ts
    verify_token(clients, auth_token1, 401)

    # set auth_token serializer back to one that doesn't expire
    app.security.remember_token_serializer = rts
    response = clients.post("/refresh-token", json={"refresh_token": refresh_token})
    new_refresh_token = response.json["response"]["user"]["refresh_token"]
    auth_token = response.json["response"]["user"]["authentication_token"]
    verify_token(clients, auth_token)

    ntdict = app.security.refresh_token_serializer.loads(new_refresh_token)
    assert (
        ntdict["expires_at"]
        > ((datetime.today() + max_age) - timedelta(days=1)).timestamp()
    )
    assert ntdict["gen"] == 2
    assert tdict["family"] == ntdict["family"]
    # mongo stores more digits...
    te = math.floor(tdict["expires_at"] * 1000.0)
    nte = math.floor(ntdict["expires_at"] * 1000.0)
    assert te == nte


@pytest.mark.app_settings(testing_no_cookies=True)
@pytest.mark.settings(refresh_token_cookie_name=None)
def test_refresh_errors(app, client, get_message):
    response = json_authenticate(client)
    refresh_token = response.json["response"]["user"]["refresh_token"]
    response = client.post("/refresh-token", json={"refresh_token": ""})
    assert response.status_code == 400
    assert response.json["response"]["errors"][0] == "This field is required."

    response = client.post("/refresh-token", json={"refresh_token": "12345"})
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "REFRESH_TOKEN_INVALID", reason=RefreshTokenErrors.INVALID.name
    )

    # This is a JSON endpoint only.
    response = client.post("/refresh-token", data={"refresh_token": refresh_token})
    assert response.status_code == 400

    # now delete the tracker from the server
    response = client.post("/refresh-token", json={"refresh_token": refresh_token})
    assert response.status_code == 200
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        assert len(user.refresh_trackers) == 1
        app.security.datastore.delete(user.refresh_trackers[0])
        app.security.datastore.commit()
    response = client.post("/refresh-token", json={"refresh_token": refresh_token})
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "REFRESH_TOKEN_INVALID", reason=RefreshTokenErrors.NOT_FOUND.name
    )


@pytest.mark.app_settings(testing_no_cookies=True)
@pytest.mark.settings(
    refresh_token_max_idle=timedelta(hours=1), refresh_token_cookie_name=None
)
def test_idle_expire(app, clients, get_message):
    response = json_authenticate(clients)
    refresh_token = response.json["response"]["user"]["refresh_token"]

    new_last_used_at = app.security.datetime_factory() - timedelta(days=1)
    _set_refresh_tracker(app, refresh_token, last_used_at=new_last_used_at)

    response = clients.post("/refresh-token", json={"refresh_token": refresh_token})
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "REFRESH_TOKEN_INVALID", reason=RefreshTokenErrors.EXPIRED.name
    )


@pytest.mark.settings(refresh_token_cookie_name=None)
def test_gen_mismatch(app, clients, get_message, signals):
    # If there is generation mismatch, the system should revoke the
    # entire refresh token family.
    response = json_authenticate(clients)

    refresh_token1 = response.json["response"]["user"]["refresh_token"]

    response = clients.post("/refresh-token", json={"refresh_token": refresh_token1})
    refresh_token2 = response.json["response"]["user"]["refresh_token"]
    auth_token2 = response.json["response"]["user"]["authentication_token"]
    verify_token(clients, auth_token2)

    # now use refresh_token1 again and the system should revoke the entire
    # refresh token family and a signal sent
    response = clients.post("/refresh-token", json={"refresh_token": refresh_token1})
    assert response.status_code == 400
    rsignal = signals["refresh_tracker_revoked"][0]
    assert rsignal["request_endpoint"] == "security.refresh_token"
    assert rsignal["refresh_errors"] == RefreshTokenErrors.GEN_MISMATCH

    # now use the supposedly good refresh_token - it too should have been revoked
    response = clients.post("/refresh-token", json={"refresh_token": refresh_token2})
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "REFRESH_TOKEN_INVALID", reason=RefreshTokenErrors.REVOKED.name
    )
    check_signals(signals, ["refresh_tracker_revoked", "refresh_tracker_created"])


@pytest.mark.app_settings(testing_no_cookies=True)
@pytest.mark.settings(refresh_token_cookie_name=None)
def test_auto_cleanup_expired(app, clients, get_message, signals):
    # test that expired refresh trackers are cleaned up as part of getting a new tracker
    response = json_authenticate(clients)
    refresh_token = response.json["response"]["user"]["refresh_token"]
    new_expires_at = app.security.datetime_factory() - timedelta(days=1)
    _set_refresh_tracker(app, refresh_token, expires_at=new_expires_at)

    response = clients.post("/refresh-token", json={"refresh_token": refresh_token})
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "REFRESH_TOKEN_INVALID", reason=RefreshTokenErrors.EXPIRED.name
    )

    # log out and back in and should get a new refresh token
    logout(clients)
    response = json_authenticate(clients)
    check_signals(signals, {"refresh_tracker_created": 2})

    with app.app_context():
        user = app.security.datastore.find_user(email="matt@lp.com")
        assert len(user.refresh_trackers) == 1


@pytest.mark.app_settings(testing_no_cookies=True)
@pytest.mark.settings(refresh_token_cookie_name=None)
def test_reset(app, clients, get_message):
    response = json_authenticate(clients)
    refresh_token = response.json["response"]["user"]["refresh_token"]

    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        assert len(user.refresh_trackers) == 1
        app.security.datastore.refresh_tracker_reset(user)
        app.security.datastore.commit()

    response = clients.post("/refresh-token", json={"refresh_token": refresh_token})
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "REFRESH_TOKEN_INVALID", reason=RefreshTokenErrors.REVOKED.name
    )


class UserWithTokenUniquifier:
    fs_token_uniquifier = Column(String(64), unique=True, nullable=False)


@pytest.mark.app_settings(
    TESTING_USER_MIXIN=UserWithTokenUniquifier, testing_no_cookies=True
)
@pytest.mark.settings(refresh_token_cookie_name=None)
@pytest.mark.changeable()
def test_token_uniquifier(app, client, get_message):
    # Test if User model has a fs_token_uniquifier field then change password doesn't
    # affect refresh tokens.
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        assert user.fs_token_uniquifier is not None

    response = json_authenticate(client)
    refresh_token = response.json["response"]["user"]["refresh_token"]
    auth_token = response.json["response"]["user"]["authentication_token"]
    headers = {"Authentication-Token": auth_token}

    response = client.post(
        "/change",
        json=dict(
            password="password",
            new_password="awesome sunset",
            new_password_confirm="awesome sunset",
        ),
        headers=headers,
    )
    assert response.status_code == 200

    response = client.post("/refresh-token", json={"refresh_token": refresh_token})
    assert response.status_code == 200


@pytest.mark.app_settings(testing_no_cookies=True)
@pytest.mark.changeable()
@pytest.mark.settings(refresh_token_cookie_name=None)
def test_no_token_uniquifier(app, client, get_message):
    # Test if User model doesn't have a fs_token_uniquifier field then change
    # password will invalidate all refresh tokens.
    response = json_authenticate(client)
    refresh_token = response.json["response"]["user"]["refresh_token"]
    auth_token = response.json["response"]["user"]["authentication_token"]
    headers = {"Authentication-Token": auth_token}

    response = client.post(
        "/change",
        json=dict(
            password="password",
            new_password="awesome sunset",
            new_password_confirm="awesome sunset",
        ),
        headers=headers,
    )
    assert response.status_code == 200

    response = client.post("/refresh-token", json={"refresh_token": refresh_token})
    assert response.status_code == 400


@pytest.mark.app_settings(testing_no_cookies=True)
@pytest.mark.settings(refresh_token_cookie_name=None)
def test_logout_with_token(app, client, get_message):
    response = json_authenticate(client)
    refresh_token = response.json["response"]["user"]["refresh_token"]
    auth_token = response.json["response"]["user"]["authentication_token"]
    headers = {"Authentication-Token": auth_token}
    client.post("/logout", json=dict(refresh_token=refresh_token), headers=headers)

    response = client.post("/refresh-token", json={"refresh_token": refresh_token})
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "REFRESH_TOKEN_INVALID", reason=RefreshTokenErrors.REVOKED.name
    )
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        assert len(user.refresh_trackers) == 1
        assert user.refresh_trackers[0].revoked_at is not None


@pytest.mark.settings(
    refresh_token_cookie_name="fs_rtoken_test",
    refresh_token_cookie=dict(
        samesite="Lax",
        httponly=True,
        secure=True,
    ),
)
def test_refresh_cookie(app, client, get_message):
    """If we configure a cookie we shouldn't get the refresh token in the response.
    The cookie should be properly updated when getting a new auth_token.
    The cookie should be deleted as part of logout.
    """
    response = json_authenticate(client)
    assert "refresh_token" not in response.json["response"]["user"]
    rcookie = client.get_cookie("fs_rtoken_test")
    assert rcookie is not None
    assert rcookie.http_only
    assert rcookie.same_site == "Lax"
    assert rcookie.secure
    tdict = app.security.refresh_token_serializer.loads(rcookie.value)
    assert tdict["gen"] == 1

    auth_token = response.json["response"]["user"]["authentication_token"]
    verify_token(client, auth_token)

    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = client.post("/refresh-token", headers=headers)
    assert response.status_code == 200

    nrcookie = client.get_cookie("fs_rtoken_test")
    assert nrcookie is not None
    assert nrcookie.http_only
    ntdict = app.security.refresh_token_serializer.loads(nrcookie.value)
    assert ntdict["gen"] == 2
    assert tdict["family"] == ntdict["family"]

    # log out and ensure cookie is removed
    client.post("/logout")
    assert client.get_cookie("fs_rtoken_test") is None
    assert len(client._cookies) == 1  # session
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        assert len(user.refresh_trackers) == 1
        assert user.refresh_trackers[0].revoked_at is not None


@pytest.mark.csrf(csrfprotect=True)
def test_refresh_token_csrf(app, client, get_message):
    csrf_token = _get_csrf_token(client)
    headers = {"X-CSRF-Token": csrf_token}

    json_authenticate(client, headers=headers)
    rcookie = client.get_cookie("fs_refresh")
    assert rcookie is not None

    response = client.post("/refresh-token", json={})
    assert response.status_code == 400
    assert response.json["response"]["errors"][0] == "The CSRF token is missing."

    client.post("/refresh-token", json={}, headers=headers)
    nrcookie = client.get_cookie("fs_refresh")
    assert nrcookie is not None
    ntdict = app.security.refresh_token_serializer.loads(nrcookie.value)
    assert ntdict["gen"] == 2

    # upon logout refresh tracker/token should have been revoked
    client.post("/logout")
    assert client.get_cookie("fs_rtoken_test") is None
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        assert len(user.refresh_trackers) == 1
        assert user.refresh_trackers[0].revoked_at is not None


@pytest.mark.settings(token_max_age=60)
def test_auth_token_max_age_int(app, client_nc):
    with app.app_context():
        with freeze_time(datetime.now(timezone.utc) + timedelta(minutes=-3)):
            response = json_authenticate(client_nc)
            token = response.json["response"]["user"]["authentication_token"]
        with pytest.raises(SignatureExpired):
            parse_auth_token(token)


@pytest.mark.settings(token_max_age=timedelta(days=3))
def test_auth_token_max_age_delta(app, client_nc):
    with app.app_context():
        with freeze_time(datetime.now(timezone.utc) + timedelta(days=-5)):
            response = json_authenticate(client_nc)
            token = response.json["response"]["user"]["authentication_token"]
        with pytest.raises(SignatureExpired):
            parse_auth_token(token)


@pytest.mark.settings(token_max_age=0)
def test_auth_token_max_age_0(app, client_nc):
    with app.app_context():
        with freeze_time(datetime.now(timezone.utc) + timedelta(weeks=-1000)):
            response = json_authenticate(client_nc)
            token = response.json["response"]["user"]["authentication_token"]
        with pytest.raises(SignatureExpired):
            parse_auth_token(token)


@pytest.mark.settings(token_max_age=timedelta(days=6))
def test_per_user_expired_token(app, client_nc):
    # Test expiry in auth_token using callable
    with app.app_context():
        with freeze_time(datetime.now(timezone.utc) + timedelta(days=-3)):

            def exp(user):
                assert user.email == "matt@lp.com"
                return int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp())

            app.config["SECURITY_TOKEN_EXPIRE_TIMESTAMP"] = exp

            response = json_authenticate(client_nc)
            token = response.json["response"]["user"]["authentication_token"]
        with pytest.raises(SignatureExpired) as e:
            parse_auth_token(token)
        assert "token[exp] value expired" in e.value.message


def test_per_user_not_expired_token(app, client_nc):
    # Test expiry in auth_token using callable
    def exp(user):
        assert user.email == "matt@lp.com"
        return int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp())

    app.config["SECURITY_TOKEN_EXPIRE_TIMESTAMP"] = exp

    response = json_authenticate(client_nc)
    token = response.json["response"]["user"]["authentication_token"]
    verify_token(client_nc, token)
