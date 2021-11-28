"""
    test_webauthn
    ~~~~~~~~~~~~~~~~~~~

    WebAuthn tests

    :copyright: (c) 2021-2021 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

"""
import datetime
from dateutil import parser
import json
import re
import typing as t

import pytest
from tests.test_utils import (
    authenticate,
    capture_flashes,
    logout,
)

from flask_security import (
    WebauthnUtil,
    user_authenticated,
)

pytest.importorskip("webauthn")

pytestmark = pytest.mark.webauthn()

# We can't/don't test the actual client-side javascript and browser APIs - so
# to create reproducible tests, use view_scaffold, set breakpoints in the browser and
# cut-and-paste the responses. That requires that 'challenge' and 'rp_origin' be
# identical between view_scaffold and tests here.
CHALLENGE = "smCCiy_k2CqQydSQ_kPEjV5a2d0ApfatcpQ1aXDmQPo"
REG_DATA1 = {
    "id": "wUUqNOjY35dcT-vpikZpZx-T91NjIe4PqrV8j7jYPOc",
    "rawId": "wUUqNOjY35dcT-vpikZpZx-T91NjIe4PqrV8j7jYPOc",
    "type": "public-key",
    "response": {
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NB"
        "cPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQAAAAAAAAAAAAAAAAAAA"
        "AAAIMFFKjTo2N-XXE_r6YpGaWcfk_dTYyHuD6q1fI-42DznpQECAy"
        "YgASFYIFRipoWMEiDuCtLUvSlqCFZBqxvUuNqZKavlWgvN2BK8Il"
        "ggLOV4eez9k0det5oIZGyKanGkmWa0hygnjjFmf8Rep6c",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYzIxR"
        "FEybDVYMnN5UTNGUmVXUlRVVjlyVUVWcVZqVmhNbVF3UVhCbVlYUmpjRk"
        "V4WVZoRWJWRlFidyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NT"
        "AwMSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
    },
    "extensions": '{"credProps": {}}',
    "transports": ["usb"],
}
SIGNIN_DATA1 = {
    "id": "wUUqNOjY35dcT-vpikZpZx-T91NjIe4PqrV8j7jYPOc",
    "rawId": "wUUqNOjY35dcT-vpikZpZx-T91NjIe4PqrV8j7jYPOc",
    "type": "public-key",
    "response": {
        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAABQ==",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYzIxRFEy"
        "bDVYMnN5UTNGUmVXUlRVVjlyVUVWcVZqVmhNbVF3UVhCbVlYUmpjRkV4"
        "WVZoRWJWRlFidyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAw"
        "MSIsImNyb3NzT3JpZ2luIjpmYWxzZX0=",
        "signature": "MEUCIH5VdRXxfnoxfrVk72gvWAn91QH-l2UrIohk5YOWi9XpAiEAn6f9oHtFS"
        "68HVf6K_Ku0L33C0sID2HzpJWSiTNgJlbU=",
    },
    "assertionClientExtensions": "{}",
}
REG_DATA2 = {
    "id": "lpMv8FTVHVSxteQJ3N4azlSxXiBJADA7IK-NleETceZYODy51_Cqt7Rx6pfVP1BI",
    "rawId": "lpMv8FTVHVSxteQJ3N4azlSxXiBJADA7IK-NleETceZYODy51_Cqt7Rx6pfVP1BI",
    "type": "public-key",
    "response": {
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjCSZYN5YgOj"
        "Gh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2PFAAAAAgAAAAAAAAAAA"
        "AAAAAAAAAAAMJaTL_BU1R1UsbXkCdzeGs5UsV4gSQAwOyCvjZXhE3"
        "HmWDg8udfwqre0ceqX1T9QSKUBAgMmIAEhWCCWky_wVNUdVL"
        "G15AncLU8mBQCtY10BjnSDoOUlRjkU1CJYIIA1U9vNDpZ"
        "TihC2x0CxRZ-trF_zazYosuEqYdHSOIjZoWtjcmVkUHJvdGVjdAI",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoi"
        "YzIxRFEybDVYMnN5UTNGUmVXUlRVVjlyVUVWcVZqVmhNbVF3UV"
        "hCbVlYUmpjRkV4WVZoRWJWRlFidyIsIm9yaWdpbiI6Imh0dHA6L"
        "y9sb2NhbGhvc3Q6NTAwMSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
    },
    "extensions": '{"credProps": {"rk": True}}',
    "transports": ["nfc", "usb"],
}


class TestWebauthnUtil(WebauthnUtil):
    def generate_challenge(self, nbytes: t.Optional[int] = None) -> str:
        return CHALLENGE

    def origin(self):
        # This is from view_scaffold
        return "http://localhost:5001"


def _register_start(client, name="testr1"):
    response = client.post("wan-register", data=dict(name=name))
    matcher = re.match(
        r".*handleRegister\(\'(.*)\'\).*",
        response.data.decode("utf-8"),
        re.IGNORECASE | re.DOTALL,
    )
    register_options = json.loads(matcher.group(1))

    action_matcher = re.match(
        r'.*<form action="([^\s]*)".*',
        response.data.decode("utf-8"),
        re.IGNORECASE | re.DOTALL,
    )
    response_url = action_matcher.group(1)
    return register_options, response_url


def _register_start_json(client, name="testr1"):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    response = client.post("wan-register", headers=headers, json=dict(name=name))
    register_options = response.json["response"]["credential_options"]
    response_url = f'wan-register/{response.json["response"]["wan_state"]}'
    return register_options, response_url


def _signin_start(client, identity=None):
    response = client.post("wan-signin", data=dict(identity=identity))
    matcher = re.match(
        r".*handleSignin\(\'(.*)\'\).*",
        response.data.decode("utf-8"),
        re.IGNORECASE | re.DOTALL,
    )
    signin_options = json.loads(matcher.group(1))

    action_matcher = re.match(
        r'.*<form action="([^\s]*)".*',
        response.data.decode("utf-8"),
        re.IGNORECASE | re.DOTALL,
    )
    response_url = action_matcher.group(1)
    return signin_options, response_url


def _signin_start_json(client, identity=None):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    response = client.post("wan-signin", headers=headers, json=dict(identity=identity))
    signin_options = response.json["response"]["credential_options"]
    response_url = f'wan-signin/{response.json["response"]["wan_state"]}'
    return signin_options, response_url


@pytest.mark.settings(webauthn_util_cls=TestWebauthnUtil)
def test_basic(app, client, get_message):
    clients = client
    auths = []

    @user_authenticated.connect_via(app)
    def authned(myapp, user, **extra_args):
        auths.append((user.email, extra_args["authn_via"]))

    authenticate(clients)

    response = clients.get("/wan-register")

    # post with no name
    response = clients.post("/wan-register", data=dict())
    assert get_message("WEBAUTHN_NAME_REQUIRED") in response.data

    register_options, response_url = _register_start(clients)
    assert register_options["rp"]["name"] == "My Flask App"
    assert register_options["user"]["name"] == "matt@lp.com"
    assert not register_options["excludeCredentials"]
    assert register_options["authenticatorSelection"]["residentKey"] == "preferred"
    assert register_options["extensions"]["credProps"]

    # Register using the static data above
    response = clients.post(
        response_url, data=dict(credential=json.dumps(REG_DATA1)), follow_redirects=True
    )
    assert response.status_code == 200
    assert get_message("WEBAUTHN_REGISTER_SUCCESSFUL", name="testr1") in response.data
    assert b"testr1" in response.data

    # sign in - simple case use identity so we get back allowCredentials
    logout(clients)
    signin_options, response_url = _signin_start(clients, "matt@lp.com")
    assert signin_options["timeout"] == app.config["SECURITY_WAN_SIGNIN_TIMEOUT"]
    assert signin_options["userVerification"] == "discouraged"
    allow_credentials = signin_options["allowCredentials"]
    assert len(allow_credentials) == 1
    assert allow_credentials[0]["id"] == REG_DATA1["id"]

    response = clients.post(
        response_url,
        data=dict(credential=json.dumps(SIGNIN_DATA1)),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Welcome matt@lp.com" in response.data
    assert len(auths) == 2
    assert auths[1][1] == ["webauthn"]

    # verify actually logged in
    response = clients.get("/profile", follow_redirects=False)
    assert response.status_code == 200


@pytest.mark.settings(webauthn_util_cls=TestWebauthnUtil)
def test_basic_json(app, client, get_message):
    clients = client
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    auths = []

    @user_authenticated.connect_via(app)
    def authned(myapp, user, **extra_args):
        auths.append((user.email, extra_args["authn_via"]))

    authenticate(clients)

    # post with no name
    response = clients.post("/wan-register", json=dict())
    assert response.status_code == 400
    assert response.json["response"]["errors"]["name"][0].encode(
        "utf-8"
    ) == get_message("WEBAUTHN_NAME_REQUIRED")

    register_options, response_url = _register_start_json(clients)
    assert register_options["rp"]["name"] == "My Flask App"
    assert register_options["user"]["name"] == "matt@lp.com"

    # Register using the static data above
    response = clients.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200

    # reset lastuse_datatime so we can verify signing in correctly alters it
    fake_dt = datetime.datetime(2020, 4, 7, 9, 27)
    with app.app_context():
        user = app.security.datastore.find_user(email="matt@lp.com")
        cred = user.webauthn[0]
        cred.lastuse_datetime = fake_dt
        app.security.datastore.put(cred)
        app.security.datastore.commit()

    response = clients.get("/wan-register", headers=headers)
    active_creds = response.json["response"]["registered_credentials"]
    assert active_creds[0]["name"] == "testr1"
    assert parser.parse(active_creds[0]["lastuse"]) == fake_dt

    # sign in - simple case use identity so we get back allowCredentials
    logout(clients)
    signin_options, response_url = _signin_start_json(clients, "matt@lp.com")
    assert signin_options["userVerification"] == "discouraged"
    allow_credentials = signin_options["allowCredentials"]
    assert len(allow_credentials) == 1
    assert allow_credentials[0]["id"] == REG_DATA1["id"]

    response = clients.post(
        response_url,
        json=dict(credential=json.dumps(SIGNIN_DATA1)),
    )
    assert response.status_code == 200
    assert auths[1][1] == ["webauthn"]

    # verify actually logged in
    response = clients.get("/profile", follow_redirects=False)
    assert response.status_code == 200

    # fetch credentials and verify lastuse was updated
    response = clients.get("/wan-register", headers=headers)
    active_creds = response.json["response"]["registered_credentials"]
    assert parser.parse(active_creds[0]["lastuse"]) != fake_dt


@pytest.mark.settings(webauthn_util_cls=TestWebauthnUtil)
def test_constraints(app, client, get_message):
    """Test that nickname is unique for a given user but different users
    can have the same nickname.
    Also that credential_id is unique across the app.
    """
    clients = client

    authenticate(clients)
    register_options, response_url = _register_start_json(clients, name="testr3")
    response = clients.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200

    # register same name again
    response = client.post("wan-register", json=dict(name="testr3"))
    assert response.status_code == 400
    assert response.json["response"]["errors"]["name"][0].encode(
        "utf-8"
    ) == get_message("WEBAUTHN_NAME_INUSE", name="testr3")

    logout(clients)

    # Different user - should get credential id in use error
    authenticate(clients, email="joe@lp.com")
    register_options, response_url = _register_start_json(clients, name="testr3")
    response = clients.post(response_url, json=dict(credential=json.dumps(REG_DATA2)))
    assert response.status_code == 200

    # Try to register with identical credential ID as other user
    register_options, response_url = _register_start_json(clients, name="testr4")
    response = clients.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 400
    assert response.json["response"]["errors"]["credential"][0].encode(
        "utf-8"
    ) == get_message("WEBAUTHN_CREDENTIAL_ID_INUSE")


@pytest.mark.settings(webauthn_util_cls=TestWebauthnUtil)
def test_delete(app, client, get_message):
    clients = client

    authenticate(client)
    register_options, response_url = _register_start(clients, name="testr3")
    response = clients.post(
        response_url, data=dict(credential=json.dumps(REG_DATA1)), follow_redirects=True
    )
    assert response.status_code == 200
    assert get_message("WEBAUTHN_REGISTER_SUCCESSFUL", name="testr3") in response.data

    response = clients.get("/wan-register")
    assert b"testr3" in response.data

    """
    response = clients.post("/wan-delete")
    assert get_message("WEBAUTHN_NAME_REQUIRED") in response.data

    response = clients.post("/wan-delete", data=dict(name="testr1"))
    assert response.status_code == 200
    assert get_message("WEBAUTHN_NAME_NOT_FOUND", name="testr1") in response.data
    """

    with capture_flashes() as flashes:
        response = clients.post(
            "/wan-delete", data=dict(name="testr3"), follow_redirects=True
        )
    assert flashes[0]["category"] == "info"
    assert flashes[0]["message"].encode("utf-8") == get_message(
        "WEBAUTHN_CREDENTIAL_DELETED", name="testr3"
    )
    response = clients.get("/wan-register")
    assert b"testr3" not in response.data


@pytest.mark.settings(webauthn_util_cls=TestWebauthnUtil)
def test_delete_json(app, client, get_message):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    clients = client

    authenticate(client)
    register_options, response_url = _register_start_json(clients, name="testr3")
    response = clients.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200

    response = clients.get("/wan-register", headers=headers)
    active_creds = response.json["response"]["registered_credentials"]
    assert active_creds[0]["name"] == "testr3"

    response = clients.post("/wan-delete", json=dict())
    assert response.status_code == 400
    assert response.json["response"]["errors"]["name"][0].encode(
        "utf=8"
    ) == get_message("WEBAUTHN_NAME_REQUIRED")

    response = clients.post("/wan-delete", json=dict(name="testr1"))
    assert response.status_code == 400
    assert response.json["response"]["errors"]["name"][0].encode(
        "utf=8"
    ) == get_message("WEBAUTHN_NAME_NOT_FOUND", name="testr1")

    response = clients.post("/wan-delete", json=dict(name="testr3"))
    assert response.status_code == 200
