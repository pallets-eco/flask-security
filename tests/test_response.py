"""
    test_response
    ~~~~~~~~~~~~~~~~~

    Tests for validating default and plugable responses.

    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import pytest

from flask import jsonify

from tests.test_utils import authenticate


def test_render_json(app, client):
    @app.security.render_json
    def my_json(payload, code, headers=None, user=None):
        return jsonify(dict(myresponse=payload, code=code))

    response = client.get(
        "/login", data={}, headers={"Content-Type": "application/json"}
    )
    assert "myresponse" in response.json
    assert response.json["code"] == 200


def _my_json(payload, code, headers=None, user=None):
    return jsonify(dict(myresponse=payload, code=code))


def test_render_json2(app, client):
    app.extensions["security"].render_json(_my_json)
    response = client.get(
        "/login", data={}, headers={"Content-Type": "application/json"}
    )
    assert "myresponse" in response.json
    assert response.json["code"] == 200


def test_render_json_logout(app, client):
    app.extensions["security"].render_json(_my_json)
    response = client.post("/logout", headers={"Content-Type": "application/json"})
    assert "myresponse" in response.json
    assert response.json["code"] == 200


def test_default_unauthn(app, client):
    """ Test default unauthn handler with and without json """

    response = client.get("/profile")
    assert response.status_code == 302
    assert response.headers["Location"] == "http://localhost/login?next=%2Fprofile"

    response = client.get("/profile", headers={"Accept": "application/json"})
    assert response.status_code == 401
    assert response.json["meta"]["code"] == 401
    # While "Basic" is acceptable, we never get a WWW-Authenticate header back since
    # most browsers intercept it.
    assert "WWW-Authenticate" not in response.headers


@pytest.mark.settings(login_url="/mylogin", url_prefix="/myprefix")
def test_default_unauthn_bp(app, client):
    """ Test default unauthn handler with blueprint prefix and login url """

    response = client.get("/profile")
    assert response.status_code == 302
    assert (
        response.headers["Location"]
        == "http://localhost/myprefix/mylogin?next=%2Fprofile"
    )


def test_default_unauthn_myjson(app, client):
    """ Make sure render_json gets called for unauthn errors """

    @app.security.render_json
    def my_json(payload, code, headers=None, user=None):
        return jsonify(dict(myresponse=payload, code=code)), code, headers

    response = client.get("/multi_auth", headers={"Accept": "application/json"})
    assert response.status_code == 401
    assert response.json["code"] == 401
    assert "myresponse" in response.json


def test_my_unauthn_handler(app, client):
    @app.security.unauthn_handler
    def my_unauthn(mechanisms, headers=None):
        return app.security._render_json({"mechanisms": mechanisms}, 401, headers, None)

    response = client.get("/multi_auth", headers={"Accept": "application/json"})
    assert response.status_code == 401
    assert all(
        m in response.json["response"]["mechanisms"]
        for m in ["session", "token", "basic"]
    )


def test_default_unauthz(app, client):
    """ Test default unauthz handler with and without json """
    authenticate(client, "joe@lp.com", "password")

    response = client.get("/admin")
    # This is the result of abort(403) since there is no UNAUTHORIZED_VIEW
    assert response.status_code == 403

    response = client.get("/admin", headers={"Accept": "application/json"})
    assert response.status_code == 403
    assert response.json["meta"]["code"] == 403


def test_default_unauthz_myjson(app, client):
    """ Make sure render_json gets called for unauthn errors """

    @app.security.render_json
    def my_json(payload, code, headers=None, user=None):
        return jsonify(dict(myresponse=payload, code=code)), code, headers

    authenticate(client, "joe@lp.com", "password")

    response = client.get("/admin", headers={"Accept": "application/json"})
    assert response.status_code == 403
    assert response.json["code"] == 403


def test_my_unauthz_handler(app, client):
    @app.security.unauthz_handler
    def my_unauthz(func, params):
        return (
            jsonify(
                dict(myresponse={"func": func.__name__, "params": params}, code=403)
            ),
            403,
        )

    authenticate(client, "joe@lp.com", "password")

    response = client.get("/admin", headers={"Accept": "application/json"})
    assert response.status_code == 403
    assert response.json["code"] == 403
    assert response.json["myresponse"]["func"] == "roles_required"
    assert response.json["myresponse"]["params"] == ["admin"]


def test_my_unauthz_handler_exc(app, client):
    """ Verify that can use exceptions in unauthz handler """

    @app.security.unauthz_handler
    def my_unauthz(func, params):
        raise ValueError("Bad Value")

    @app.errorhandler(ValueError)
    def error_handler(ex):
        return jsonify(dict(code=403)), 403

    authenticate(client, "joe@lp.com", "password")

    response = client.get("/admin", headers={"Accept": "application/json"})
    assert response.status_code == 403
