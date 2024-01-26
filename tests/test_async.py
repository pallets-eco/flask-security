"""
    test_async
    ~~~~~~~~~~

    Tests using Flask async.

    Make sure our decorators allow for async views
    Make sure signal receivers can be async

    :copyright: (c) 2023-2023 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

"""

import asyncio
import base64

import pytest

from flask_principal import identity_changed

from flask_security import (
    anonymous_user_required,
    auth_token_required,
    auth_required,
    http_auth_required,
    roles_required,
    roles_accepted,
    permissions_required,
    permissions_accepted,
    unauth_csrf,
)

from tests.test_utils import (
    authenticate,
    json_authenticate,
)

pytestmark = pytest.mark.flask_async()


def test_auth_required(app, client):
    @app.route("/async_test")
    @auth_required()
    async def async_test():
        await asyncio.sleep(0)
        return "Access Granted"

    authenticate(client)
    response = client.get("/async_test")
    assert b"Access Granted" in response.data


def test_auth_token_required(app, client):
    @app.route("/async_test")
    @auth_token_required
    async def async_test():
        await asyncio.sleep(0)
        return "Access Granted"

    @identity_changed.connect_via(app)
    async def ic(myapp, identity, **extra_args):
        await asyncio.sleep(0)

    response = json_authenticate(client)
    token = response.json["response"]["user"]["authentication_token"]
    response = client.get("/async_test?auth_token=" + token)
    assert b"Access Granted" in response.data


def test_auth_http_required(app, client):
    @app.route("/async_test")
    @http_auth_required
    async def async_test():
        await asyncio.sleep(0)
        return "Access Granted"

    response = client.get(
        "/async_test",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"joe@lp.com:password").decode("utf-8")
        },
    )
    assert b"Access Granted" in response.data


def test_roles_required(app, client):
    @app.route("/async_test")
    @roles_required("admin")
    async def async_test():
        await asyncio.sleep(0)
        return "Access Granted"

    authenticate(client)
    response = client.get("/async_test")
    assert b"Access Granted" in response.data


def test_roles_accepted(app, client):
    @app.route("/async_test")
    @roles_accepted("admin")
    async def async_test():
        await asyncio.sleep(0)
        return "Access Granted"

    authenticate(client)
    response = client.get("/async_test")
    assert b"Access Granted" in response.data


def test_permissions_required(app, client):
    @app.route("/async_test")
    @permissions_required("super")
    async def async_test():
        await asyncio.sleep(0)
        return "Access Granted"

    authenticate(client)
    response = client.get("/async_test")
    assert b"Access Granted" in response.data


def test_permissions_accepted(app, client):
    @app.route("/async_test")
    @permissions_accepted("super")
    async def async_test():
        await asyncio.sleep(0)
        return "Access Granted"

    authenticate(client)
    response = client.get("/async_test")
    assert b"Access Granted" in response.data


def test_anon(app, client):
    @app.route("/async_test")
    @anonymous_user_required
    async def async_test():
        await asyncio.sleep(0)
        return "Access Granted"

    response = client.get("/async_test")
    assert b"Access Granted" in response.data


def test_unauth_csrf(app, client):
    @app.route("/async_test")
    @unauth_csrf()
    async def async_test():
        await asyncio.sleep(0)
        return "Access Granted"

    response = client.get("/async_test")
    assert b"Access Granted" in response.data
