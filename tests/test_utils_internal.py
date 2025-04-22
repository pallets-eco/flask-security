import pytest
import time
import re
from datetime import timedelta
from flask_security import Security, UserMixin
from flask import Flask, flash, Response

from tests.test_utils import (
    convert_bool_option,
    FakeSerializer,
    reset_fresh,
    get_auth_token_version_3x,
    get_auth_token_version_4x,
    get_form_input_value,
    get_session,
    capture_flashes,
)


class DummyUser(UserMixin):
    def __init__(self, id=None, password=None, fs_uniquifier=None):
        self.id = id
        self.password = password
        self.fs_uniquifier = fs_uniquifier


def test_convert_bool_option():
    assert convert_bool_option("True") is True
    assert convert_bool_option("False") is False
    assert convert_bool_option("other") == "other"


def test_fake_serializer_loads_expired():
    fs = FakeSerializer(age=5)
    with pytest.raises(Exception) as e:
        fs.loads("token", max_age=5)
    assert "expired" in str(e.value)


def test_fake_serializer_loads_invalid():
    fs = FakeSerializer(invalid=True)
    with pytest.raises(Exception) as e:
        fs.loads("token", max_age=10)
    assert "bad" in str(e.value)


def test_fake_serializer_dumps():
    fs = FakeSerializer()
    assert fs.dumps({}) == "heres your state"


def test_reset_fresh_sets_old_timestamp(app, client):
    with client.session_transaction() as sess:
        sess["fs_paa"] = time.time()
    old = reset_fresh(client, within=timedelta(seconds=10))
    with client.session_transaction() as sess:
        assert sess["fs_paa"] == old


def test_get_auth_token_version_3x(app):
    dummy = DummyUser(id=1, password="supersecure")

    app.config["SECRET_KEY"] = "super-secret"
    app.config["SECURITY_PASSWORD_SALT"] = "salty"

    class DummyDatastore:
        pass

    app.security = Security(app, datastore=DummyDatastore())

    with app.app_context():
        token = get_auth_token_version_3x(app, dummy)
        assert isinstance(token, str)


def test_get_auth_token_version_4x(app):
    dummy = DummyUser(fs_uniquifier="ABC123")

    app.config["SECRET_KEY"] = "super-secret"
    app.config["SECURITY_PASSWORD_SALT"] = "salty"

    class DummyDatastore:
        pass

    app.security = Security(app, datastore=DummyDatastore())

    with app.app_context():
        token = get_auth_token_version_4x(app, dummy)
        assert isinstance(token, str)


# New additions

def test_get_form_input_value_extracts_correct_value():
    html = b'''
    <form>
      <input type="text" id="username" value="nick123">
      <input type="password" id="password" value="secret">
    </form>
    '''
    class DummyResponse:
        data = html

    value = get_form_input_value(DummyResponse(), "username")
    assert value == "nick123"


def test_get_session_returns_dict(app, client):
    with client:
        with client.session_transaction() as sess:
            sess["test_key"] = "test_value"
        response = client.get("/")
        session_data = get_session(response)
        assert session_data.get("test_key") == "test_value"


def test_capture_flashes_works(app):
    with app.test_request_context("/"):
        with capture_flashes() as flashes:
            flash("Test message", "info")
        assert len(flashes) == 1
        assert flashes[0]["message"] == "Test message"
        assert flashes[0]["category"] == "info"
