"""
test_tokens
~~~~~~~~~~~~~~~~

Refresh/Auth Token functionality tests

:copyright: (c) 2026-2026 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.
"""

from datetime import datetime, timedelta
import math

import pytest
from sqlalchemy import Column, String

from flask_security.datastore import PeeweeDatastore
from flask_security.tokens import RefreshTokenErrors
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
def test_refresh(app, clients, get_message):
    """Test basic refresh token flow.
    - authenticate and receive auth_token and refresh_token
    - we hack the auth_token to be already expired
    - we should get a 401 when using it
    - use the /refresh-token endpoint to get a new refresh_token and auth_token
    - auth_token should be valid
    """
    start_ts = datetime.today().timestamp()
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
@pytest.mark.settings(refresh_token_max_idle=timedelta(hours=1))
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
