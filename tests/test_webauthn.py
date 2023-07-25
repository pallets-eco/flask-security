"""
    test_webauthn
    ~~~~~~~~~~~~~~~~~~~

    WebAuthn tests

    :copyright: (c) 2021-2023 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

"""

from base64 import urlsafe_b64encode
import copy
import datetime
from dateutil import parser
import json
import re
import typing as t

import pytest

from tests.test_two_factor import tf_in_session
from tests.test_utils import (
    FakeSerializer,
    authenticate,
    capture_flashes,
    get_existing_session,
    get_form_action,
    json_authenticate,
    logout,
    reset_fresh,
    setup_tf_sms,
)

from flask_security import (
    WebauthnUtil,
    user_authenticated,
    wan_registered,
    wan_deleted,
)

pytestmark = pytest.mark.webauthn()

# We can't/don't test the actual client-side javascript and browser APIs - so
# to create reproducible tests, use view_scaffold, set breakpoints in the views and
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
        "transports": ["usb"],
    },
    "extensions": '{"credProps": {}}',
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
        "transports": ["nfc", "usb"],
    },
    "extensions": '{"credProps": {"rk": True}}',
}

# This has user_verification=True - i.e. a multi-factor capable key
REG_DATA_UV = {
    "id": "s3xZpfGy0ZH-sSkfxIsgChwbkw_O0jOFtZeJ1LXUMEa8atG1oEskNqmFJCfgKZGy",
    "rawId": "s3xZpfGy0ZH-sSkfxIsgChwbkw_O0jOFtZeJ1LXUMEa8atG1oEskNqmFJCfgKZGy",
    "type": "public-key",
    "response": {
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjC"
        "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2PFAAAABAAAAA"
        "AAAAAAAAAAAAAAAAAAMLN8WaXxstGR_rEpH8SLIAocG5MPztIzhbWXi"
        "dS11DBGvGrRtaBLJDaphSQn4CmRsqUBAgMmIAEhWCCzfFml8bLRkf"
        "6xKR_EUnaoI333MuxRlv5-LwojDibdTyJYIFMifFwn-RfkDDgsTHF"
        "jWgE6bld-Jc4nhFMTkQja9P8IoWtjcmVkUHJvdGVjdAI",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYzI"
        "xRFEybDVYMnN5UTNGUmVXUlRVVjlyVUVWcVZqVmhNbVF3UVhCbVlY"
        "UmpjRkV4WVZoRWJWRlFidyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2Nhb"
        "Ghvc3Q6NTAwMSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
        "transports": ["nfc", "usb"],
    },
    "extensions": '{"credProps":{"rk":true}}',
}

SIGNIN_DATA_UV = {
    "id": "s3xZpfGy0ZH-sSkfxIsgChwbkw_O0jOFtZeJ1LXUMEa8atG1oEskNqmFJCfgKZGy",
    "rawId": "s3xZpfGy0ZH-sSkfxIsgChwbkw_O0jOFtZeJ1LXUMEa8atG1oEskNqmFJCfgKZGy",
    "type": "public-key",
    "response": {
        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAABQ==",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYzIxRFEy"
        "bDVYMnN5UTNGUmVXUlRVVjlyVUVWcVZqVmhNbVF3UVhCbVlYUmpjRkV4W"
        "VZoRWJWRlFidyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMSI"
        "sImNyb3NzT3JpZ2luIjpmYWxzZX0=",
        "signature": "MEUCIQDR0m9Ob4nqVGiAPUf1Tu5XohDh2frl1LJ6G41GURlUIgIgKUPfkw"
        "AjP2863L2nDhcR2EKqoGEQLqlQ5xymZstyO6o=",
    },
    "assertionClientExtensions": "{}",
}

REG_DATA_UH = {
    "id": "rHb1OXVM--dgGcWg0u3cfomyc-Tu4l4kK8GjVkS8bms-foXmBAlWHyTzuhgGgCnx",
    "rawId": "rHb1OXVM--dgGcWg0u3cfomyc-Tu4l4kK8GjVkS8bms-foXmBAlWHyTzuhgGgCnx",
    "type": "public-key",
    "response": {
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjCSZYN5YgOjGh0NBc"
        "PZHZgW4_krrmihjLHmVzzuoMd"
        "l2PFAAAAAgAAAAAAAAAAAAAAAAAAAAAAMKx29Tl1TPvnYBnFoNLt3H6J"
        "snPk7uJeJCvBo1ZEvG5rPn6F"
        "5gQJVh8k87oYBoAp8aUBAgMmIAEhWCCsdvU5dUz752AZxaDSyN-ocBL"
        "Bo99GevEWTnUxSkMRICJYIILE"
        "DLF8cQNM5l6ZgDxIYpvU88xgbq44lmR6oCBbNaHhoWtjcmVkUHJvdG"
        "VjdAI",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYzIx"
        "RFEybDVYMnN5UTNGUmVXUlRVVjl"
        "yVUVWcVZqVmhNbVF3UVhCbVlYUmpjRkV4WVZoRWJWRlFidyIsIm9yaWdpbi"
        "I6Imh0dHA6Ly9sb2NhbGhvc3"
        "Q6NTAwMSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
        "transports": ["nfc", "usb"],
    },
    "extensions": '{"credProps":{"rk": true}}"',
}
SIGNIN_DATA_UH = {
    "id": "rHb1OXVM--dgGcWg0u3cfomyc-Tu4l4kK8GjVkS8bms-foXmBAlWHyTzuhgGgCnx",
    "rawId": "rHb1OXVM--dgGcWg0u3cfomyc-Tu4l4kK8GjVkS8bms-foXmBAlWHyTzuhgGgCnx",
    "type": "public-key",
    "response": {
        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAABQ==",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYzIxRFEy"
        "bDVYMnN5UTNGUmVXUlRVVjlyVUVWcVZqVmhNbVF3UVhCbVlYUmpjR"
        "kV4WVZoRWJWRlFidyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q"
        "6NTAwMSIsImNyb3NzT3JpZ2luIjpmYWxzZX0=",
        "signature": "MEUCIQCbKwaQv_GzrWfc0nVXqhe6WZs_5Sb2b7xHC9iDW9aHeQIgF2PlfM7FdyV"
        "xcPhofekJjLBgDMTbK4mwIWHgiExZ54s=",
        "userHandle": "NTgxMTU3YmM2MGU3NGM1OTg0OTBjYTI1ZTgwNjc4MDY=",
    },
    "assertionClientExtensions": "{}",
}


class HackWebauthnUtil(WebauthnUtil):
    def generate_challenge(self, nbytes: t.Optional[int] = None) -> str:
        return CHALLENGE

    def origin(self):
        # This is from view_scaffold
        return "http://localhost:5001"


def _register_start(client, name="testr1", usage="secondary", endpoint="wan-register"):
    response = client.post(endpoint, data=dict(name=name, usage=usage))
    matcher = re.match(
        r".*handleRegister\(\'(.*)\'\).*",
        response.data.decode("utf-8"),
        re.IGNORECASE | re.DOTALL,
    )
    register_options = json.loads(matcher.group(1))
    response_url = get_form_action(response)
    return register_options, response_url


def _register_start_json(client, name="testr1", usage="secondary"):
    response = client.post("wan-register", json=dict(name=name, usage=usage))
    register_options = response.json["response"]["credential_options"]
    response_url = f'wan-register/{response.json["response"]["wan_state"]}'
    return register_options, response_url


def reg_2_keys(client):
    # Register 2 keys - one first, one secondary
    # This can be used by other tests outside this module.
    authenticate(client)
    register_options, response_url = _register_start_json(
        client, name="first", usage="first"
    )
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA_UV)))
    assert response.status_code == 200

    register_options, response_url = _register_start_json(
        client, name="second", usage="secondary"
    )
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200

    return {
        "first": {"id": REG_DATA_UV["id"], "signin": SIGNIN_DATA_UV},
        "secondary": {"id": REG_DATA1["id"], "signin": SIGNIN_DATA1},
    }


def _signin_start(
    client,
    identity=None,
    endpoint="wan-signin",
):
    response = client.post(endpoint, data=dict(identity=identity))
    matcher = re.match(
        r".*handleSignin\(\'(.*)\'\).*",
        response.data.decode("utf-8"),
        re.IGNORECASE | re.DOTALL,
    )
    signin_options = json.loads(matcher.group(1))
    response_url = get_form_action(response)
    return signin_options, response_url


def _signin_start_json(client, identity=None, remember=False, endpoint="wan-signin"):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    response = client.post(
        endpoint, headers=headers, json=dict(identity=identity, remember=remember)
    )
    signin_options = response.json["response"]["credential_options"]
    response_url = f'wan-signin/{response.json["response"]["wan_state"]}'
    return signin_options, response_url, response.json


def wan_signin(client, identity, signin_data, wan_signin_url):
    # perform complete sign in - useful for tests outside this module.
    signin_options, response_url = _signin_start(
        client, identity, endpoint=wan_signin_url
    )
    response = client.post(
        response_url,
        data=dict(credential=json.dumps(signin_data)),
        follow_redirects=True,
    )
    assert response.status_code == 200
    return response


def reset_signcount(app, email, keyname):
    # Due to replay attack prevention, we can only use a key once since the server
    # increments the sign_count and we can't do that on the client side!
    with app.app_context():
        user = app.security.datastore.find_user(email=email)
        cred = [c for c in user.webauthn if c.name == keyname][0]
        cred.sign_count = cred.sign_count - 1
        app.security.datastore.put(cred)
        app.security.datastore.commit()


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_basic(app, clients, get_message):
    auths = []

    @user_authenticated.connect_via(app)
    def authned(myapp, user, **extra_args):
        auths.append((user.email, extra_args["authn_via"]))

    @wan_registered.connect_via(app)
    def pc(sender, user, name, **extra_args):
        assert name == "testr1"
        assert len(user.webauthn) == 1

    authenticate(clients)

    response = clients.get("/wan-register")

    # post with no name
    response = clients.post("/wan-register", data=dict())
    assert get_message("WEBAUTHN_NAME_REQUIRED") in response.data

    register_options, response_url = _register_start(clients, usage="first")
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
    assert signin_options["userVerification"] == "preferred"
    allow_credentials = signin_options["allowCredentials"]
    assert len(allow_credentials) == 1
    assert allow_credentials[0]["id"] == REG_DATA1["id"]
    assert allow_credentials[0]["transports"] == ["usb"]

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


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_basic_json(app, clients, get_message):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    auths = []

    @user_authenticated.connect_via(app)
    def authned(myapp, user, **extra_args):
        auths.append((user.email, extra_args["authn_via"]))

    authenticate(clients)

    # post with no name
    response = clients.post("/wan-register", json=dict())
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "WEBAUTHN_NAME_REQUIRED"
    )

    register_options, response_url = _register_start_json(clients, usage="first")
    assert register_options["rp"]["name"] == "My Flask App"
    assert register_options["user"]["name"] == "matt@lp.com"

    # Register using the static data above
    response = clients.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200

    # reset lastuse_datetime so we can verify signing in correctly alters it
    fake_dt = datetime.datetime(2020, 4, 7, 9, 27)
    with app.app_context():
        user = app.security.datastore.find_user(email="matt@lp.com")
        for cred in user.webauthn:
            cred.lastuse_datetime = fake_dt
            app.security.datastore.put(cred)
        app.security.datastore.commit()
        if hasattr(app.security.datastore.db, "close_db") and callable(
            app.security.datastore.db.close_db
        ):
            app.security.datastore.db.close_db(None)

    response = clients.get("/wan-register", headers=headers)
    active_creds = response.json["response"]["registered_credentials"]
    assert active_creds[0]["name"] == "testr1"
    assert parser.parse(active_creds[0]["lastuse"]) == fake_dt

    # sign in - simple case use identity so we get back allowCredentials
    logout(clients)
    signin_options, response_url, rjson = _signin_start_json(clients, "matt@lp.com")
    assert signin_options["userVerification"] == "preferred"
    allow_credentials = signin_options["allowCredentials"]
    assert len(allow_credentials) == 1
    assert allow_credentials[0]["id"] == REG_DATA1["id"]
    assert "user" not in rjson["response"]

    response = clients.post(
        response_url,
        json=dict(credential=json.dumps(SIGNIN_DATA1)),
    )
    assert response.status_code == 200
    assert response.json["response"]["user"]["email"] == "matt@lp.com"
    assert auths[1][1] == ["webauthn"]

    # verify actually logged in
    response = clients.get("/profile", follow_redirects=False)
    assert response.status_code == 200

    # fetch credentials and verify lastuse was updated
    response = clients.get("/wan-register", headers=headers)
    active_creds = response.json["response"]["registered_credentials"]
    assert parser.parse(active_creds[0]["lastuse"]) != fake_dt
    assert active_creds[0]["transports"] == ["usb"]
    assert active_creds[0]["usage"] == "first"

    logout(clients)
    # verify that unknown identities are just ignored when USER_HINTS is True
    response = clients.post("/wan-signin", json=dict(identity="whoami@lp.com"))
    assert response.status_code == 200


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil, wan_allow_user_hints=False)
def test_basic_json_nohints(app, client, get_message):
    # Test that with no hints allowed, we don't get any credentials and we can still
    # sign in.
    authenticate(client)
    register_options, response_url = _register_start_json(client, usage="first")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200
    # With no hints we default to requiring a resident key
    # With allow as primary we default to requiring a cross-platform key
    assert (
        register_options["authenticatorSelection"]["authenticatorAttachment"]
        == "cross-platform"
    )
    assert register_options["authenticatorSelection"]["residentKey"] == "required"
    logout(client)

    signin_options, response_url, rjson = _signin_start_json(client, "matt@lp.com")
    allow_credentials = signin_options["allowCredentials"]
    assert len(allow_credentials) == 0
    assert "user" not in rjson["response"]

    response = client.post(
        response_url,
        json=dict(credential=json.dumps(SIGNIN_DATA1)),
    )
    assert response.status_code == 200
    assert response.json["response"]["user"]["email"] == "matt@lp.com"


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_usage(app, client, get_message):
    authenticate(client)
    register_options, response_url = _register_start_json(client, usage="secondary")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200
    logout(client)

    signin_options, response_url, _ = _signin_start_json(client, "matt@lp.com")
    response = client.post(
        response_url,
        json=dict(credential=json.dumps(SIGNIN_DATA1)),
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "WEBAUTHN_CREDENTIAL_WRONG_USAGE"
    )


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_constraints(app, clients, get_message):
    """Test that nickname is unique for a given user but different users
    can have the same nickname.
    Also that credential_id is unique across the app.
    """
    authenticate(clients)
    register_options, response_url = _register_start_json(clients, name="testr3")
    response = clients.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200

    # register same name again
    response = clients.post("wan-register", json=dict(name="testr3"))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "WEBAUTHN_NAME_INUSE", name="testr3"
    )

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
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "WEBAUTHN_CREDENTIAL_ID_INUSE"
    )


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_bad_data_register(app, client, get_message):
    authenticate(client)
    register_options, response_url = _register_start_json(client, name="testr3")

    # first try mangling json - should get API_ERROR
    response = client.post(response_url, json=dict(credential="hi there"))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "API_ERROR"
    )

    # Now pass incorrect keys
    bad_register = copy.deepcopy(REG_DATA1)
    del bad_register["rawId"]
    response = client.post(response_url, json=dict(credential=json.dumps(bad_register)))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "API_ERROR"
    )

    # now muck with attestation - should get VERIFY ERROR
    bad_register = copy.deepcopy(REG_DATA1)
    bad_register["rawId"] = "unknown"
    response = client.post(response_url, json=dict(credential=json.dumps(bad_register)))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "WEBAUTHN_NO_VERIFY", cause="id and raw_id were not equivalent"
    )

    # same with forms
    with capture_flashes() as flashes:
        response = client.post(
            response_url,
            data=dict(credential=json.dumps(bad_register)),
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "/wan-register" in response.location
    assert flashes[0]["category"] == "error"
    assert flashes[0]["message"].encode("utf-8") == get_message(
        "WEBAUTHN_NO_VERIFY", cause="id and raw_id were not equivalent"
    )


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_bad_data_signin(app, client, get_message):
    authenticate(client)
    register_options, response_url = _register_start_json(client, usage="first")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200

    logout(client)
    signin_options, response_url, _ = _signin_start_json(client, "matt@lp.com")
    response = client.post(response_url, json=dict(credential="hi there"))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "API_ERROR"
    )

    # Now pass incorrect keys
    bad_signin = copy.deepcopy(SIGNIN_DATA1)
    del bad_signin["rawId"]
    response = client.post(response_url, json=dict(credential=json.dumps(bad_signin)))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "API_ERROR"
    )

    # now muck with attestation - should get VERIFY ERROR
    bad_signin = copy.deepcopy(SIGNIN_DATA1)
    bad_signin["response"]["signature"] = bad_signin["response"]["signature"].replace(
        "M", "N"
    )
    response = client.post(response_url, json=dict(credential=json.dumps(bad_signin)))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "WEBAUTHN_NO_VERIFY", cause="Could not verify authentication signature"
    )


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_delete(app, clients, get_message):
    @wan_deleted.connect_via(app)
    def pc(sender, user, name, **extra_args):
        assert name == "testr3"
        assert len(user.webauthn) == 1

    authenticate(clients)
    register_options, response_url = _register_start(clients, name="testr3")
    response = clients.post(
        response_url, data=dict(credential=json.dumps(REG_DATA1)), follow_redirects=True
    )
    assert response.status_code == 200
    assert get_message("WEBAUTHN_REGISTER_SUCCESSFUL", name="testr3") in response.data

    response = clients.get("/wan-register")
    assert b"testr3" in response.data

    # Make sure GET works - this is important if we get a freshness redirect when
    # attempting to delete - the verify endpoint will redirect back to here.
    response = clients.get("/wan-delete", follow_redirects=False)
    assert response.status_code == 302

    """
    response = clients.post("/wan-delete")
    assert get_message("WEBAUTHN_NAME_REQUIRED") in response.data
    """

    response = clients.post(
        "/wan-delete", data=dict(name="testr1"), follow_redirects=True
    )
    assert get_message("WEBAUTHN_NAME_NOT_FOUND", name="testr1") in response.data

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


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_delete_json(app, clients, get_message):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    authenticate(clients)
    register_options, response_url = _register_start_json(clients, name="testr3")
    response = clients.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200

    response = clients.get("/wan-register", headers=headers)
    active_creds = response.json["response"]["registered_credentials"]
    assert active_creds[0]["name"] == "testr3"

    response = clients.post("/wan-delete", json=dict())
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf=8") == get_message(
        "WEBAUTHN_NAME_REQUIRED"
    )

    response = clients.post("/wan-delete", json=dict(name="testr1"))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf=8") == get_message(
        "WEBAUTHN_NAME_NOT_FOUND", name="testr1"
    )

    response = clients.post("/wan-delete", json=dict(name="testr3"))
    assert response.status_code == 200


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_disabled_account(app, client, get_message):
    # With USER_HINTS enabled, should get 200 on initial signin POST, but
    # not receive a list of registered credentials.
    authenticate(client)

    register_options, response_url = _register_start_json(
        client, name="testr3", usage="first"
    )
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200
    logout(client)

    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        app.security.datastore.deactivate_user(user)
        app.security.datastore.commit()

    signin_options, response_url = _signin_start(client, "matt@lp.com")
    assert response.status_code == 200
    allow_credentials = signin_options["allowCredentials"]
    assert len(allow_credentials) == 0

    # Now set USER_HINTS false and should get 400 on second POST
    app.config["SECURITY_WAN_ALLOW_USER_HINTS"] = False

    # Identity should be ignored
    signin_options, response_url = _signin_start(client, "matt@lp.com")
    allow_credentials = signin_options["allowCredentials"]
    assert len(allow_credentials) == 0

    response = client.post(
        response_url,
        json=dict(credential=json.dumps(SIGNIN_DATA1)),
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "DISABLED_ACCOUNT"
    )


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_unk_credid(app, client, get_message):
    authenticate(client)

    register_options, response_url = _register_start_json(
        client, name="testr3", usage="first"
    )
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200
    logout(client)

    signin_options, response_url, _ = _signin_start_json(client, "matt@lp.com")
    assert len(signin_options["allowCredentials"]) == 1

    bad_signin = copy.deepcopy(SIGNIN_DATA1)
    bad_signin["rawId"] = bad_signin["rawId"].replace("w", "d")

    response = client.post(
        response_url,
        json=dict(credential=json.dumps(bad_signin)),
    )
    assert response.status_code == 400
    assert response.json["response"]["field_errors"]["credential"][0].encode(
        "utf-8"
    ) == get_message("WEBAUTHN_UNKNOWN_CREDENTIAL_ID")

    # same with forms
    with capture_flashes() as flashes:
        response = client.post(
            response_url,
            data=dict(credential=json.dumps(bad_signin)),
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "/wan-signin" in response.location
    assert flashes[0]["category"] == "error"
    assert flashes[0]["message"].encode("utf-8") == get_message(
        "WEBAUTHN_UNKNOWN_CREDENTIAL_ID"
    )


@pytest.mark.settings(
    webauthn_util_cls=HackWebauthnUtil,
    wan_allow_as_first_factor=False,
)
def test_no_first_factor(app, client, get_message):
    # make sure that is app not configured to allow a webauthn key as a 'first'
    # authenticator, that the endpoint 'disappears'.
    authenticate(client)

    register_options, response_url = _register_start_json(client, name="testr3")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200
    logout(client)

    response = client.post("wan-signin", json=dict(identity="matt@lp.com"))
    assert response.status_code == 404


@pytest.mark.two_factor()
@pytest.mark.unified_signin()
@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_tf(app, client, get_message):
    # Test using webauthn key as a second factor
    # Register 2 keys - one "first" one "secondary"
    keys = reg_2_keys(client)
    logout(client)

    # log back in - should require MFA.
    response = client.post(
        "/us-signin",
        data=dict(identity="matt@lp.com", passcode="password", remember=True),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Use Your WebAuthn Security Key as a Second Factor" in response.data
    # we should have a wan key available
    assert b'action="/wan-signin' in response.data

    # verify NOT logged in
    response = client.get("/profile", follow_redirects=False)
    assert "/login" in response.location

    signin_options, response_url = _signin_start(client, "matt@lp.com")
    assert len(signin_options["allowCredentials"]) == 1
    assert signin_options["allowCredentials"][0]["id"] == keys["secondary"]["id"]
    response = client.post(
        response_url,
        json=dict(credential=json.dumps(keys["secondary"]["signin"])),
    )
    assert response.status_code == 200

    # verify actually logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200


@pytest.mark.two_factor()
@pytest.mark.unified_signin()
@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_tf_json(app, client, get_message):
    # Test using webauthn key as a second factor
    # Register 2 keys - one "first" one "secondary"
    keys = reg_2_keys(client)
    logout(client)

    # log back in - should require MFA.
    response = client.post(
        "/us-signin",
        json=dict(identity="matt@lp.com", passcode="password", remember=True),
    )
    assert response.status_code == 200
    assert response.json["response"]["tf_method"] == "webauthn"
    assert response.json["response"]["tf_required"]
    assert response.json["response"]["tf_state"] == "ready"
    assert response.json["response"]["tf_signin_url"] == "/wan-signin"

    # verify NOT logged in
    response = client.get("/profile", headers={"accept": "application/json"})
    assert response.status_code == 401

    # For secondary, identity is stored in session
    signin_options, response_url, _ = _signin_start_json(client, "")
    assert len(signin_options["allowCredentials"]) == 1
    assert signin_options["allowCredentials"][0]["id"] == keys["secondary"]["id"]
    response = client.post(
        response_url,
        json=dict(credential=json.dumps(keys["secondary"]["signin"])),
    )
    assert response.status_code == 200

    # verify actually logged in
    response = client.get("/profile", headers={"accept": "application/json"})
    assert response.status_code == 200


@pytest.mark.two_factor()
@pytest.mark.settings(
    webauthn_util_cls=HackWebauthnUtil, two_factor_always_validate=False
)
def test_tf_validity_window(app, client, get_message):
    # Test with a two-factor validity setting - we don't get re-prompted.
    authenticate(client)
    assert not client.get_cookie("tf_validity")
    register_options, response_url = _register_start_json(client)
    client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    logout(client)

    # login - should require second factor
    response = client.post(
        "/login",
        data=dict(email="matt@lp.com", password="password"),
        follow_redirects=True,
    )
    assert b"Use Your WebAuthn Security Key as a Second Factor" in response.data
    with client.session_transaction() as session:
        assert "tf_user_id" in session

    signin_options, response_url = _signin_start(client, "matt@lp.com")
    response = client.post(response_url, json=dict(credential=json.dumps(SIGNIN_DATA1)))
    assert response.status_code == 200

    # verify actually logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200
    reset_signcount(app, "matt@lp.com", "testr1")
    logout(client)

    # since we didn't specify 'remember' previously - should still require 2FA
    response = client.post(
        "/login",
        data=dict(email="matt@lp.com", password="password", remember=True),
        follow_redirects=True,
    )
    assert b"Use Your WebAuthn Security Key as a Second Factor" in response.data

    signin_options, response_url = _signin_start(client, "matt@lp.com")
    response = client.post(response_url, json=dict(credential=json.dumps(SIGNIN_DATA1)))
    assert response.status_code == 200
    assert client.get_cookie("tf_validity")
    logout(client)

    # since we did specify 'remember' previously - should not require 2FA
    response = client.post(
        "/login",
        data=dict(email="matt@lp.com", password="password"),
        follow_redirects=True,
    )
    # verify actually logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200

    # Since logged in all tf related attributes in session should be gone.
    assert not tf_in_session(get_existing_session(client))


@pytest.mark.two_factor()
@pytest.mark.settings(
    webauthn_util_cls=HackWebauthnUtil, two_factor_always_validate=False
)
def test_tf_validity_window_json(app, client, get_message):
    # Test with a two-factor validity setting - we don't get re-prompted.
    # This also relies on the tf_validity_cookie
    json_authenticate(client)
    register_options, response_url = _register_start_json(client)
    client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    logout(client)

    response = client.post(
        "/login", json=dict(email="matt@lp.com", password="password", remember=True)
    )
    assert response.status_code == 200
    assert response.json["response"]["tf_required"]

    signin_options, response_url = _signin_start(client, "matt@lp.com")
    response = client.post(response_url, json=dict(credential=json.dumps(SIGNIN_DATA1)))
    assert response.status_code == 200
    logout(client)

    # Sign in again - shouldn't require 2FA
    response = client.post(
        "/login",
        json=dict(
            email="matt@lp.com",
            password="password",
            remember=True,
        ),
    )
    assert response.status_code == 200
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200


@pytest.mark.settings(
    webauthn_util_cls=HackWebauthnUtil, wan_register_within="1 seconds"
)
def test_register_timeout(app, client, get_message):
    authenticate(client)

    app.security.wan_serializer = FakeSerializer(1.0)
    register_options, response_url = _register_start_json(client, name="testr3")

    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "WEBAUTHN_EXPIRED", within=app.config["SECURITY_WAN_REGISTER_WITHIN"]
    )


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil, wan_signin_within="2 seconds")
def test_signin_timeout(app, client, get_message):
    authenticate(client)

    register_options, response_url = _register_start_json(client, name="testr3")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200
    logout(client)

    app.security.wan_serializer = FakeSerializer(2.0)
    signin_options, response_url, _ = _signin_start_json(client, "matt@lp.com")
    response = client.post(
        response_url,
        json=dict(credential=json.dumps(SIGNIN_DATA1)),
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "WEBAUTHN_EXPIRED", within=app.config["SECURITY_WAN_SIGNIN_WITHIN"]
    )


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_bad_token(app, client, get_message):
    authenticate(client)

    response = client.post("/wan-register/not a token", json=dict())
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "API_ERROR"
    )
    # same w/o json
    response = client.post(
        "/wan-register/not a token", data=dict(), follow_redirects=True
    )
    assert get_message("API_ERROR") in response.data
    response = client.post(
        "/wan-register/not a token", data=dict(), follow_redirects=False
    )
    assert "/wan-register" in response.location

    # Test wan-verify
    response = client.post("/wan-verify/not a token", json=dict())
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "API_ERROR"
    )
    # same w/o json
    response = client.post(
        "/wan-verify/not a token", data=dict(), follow_redirects=True
    )
    assert get_message("API_ERROR") in response.data
    response = client.post(
        "/wan-verify/not a token", data=dict(), follow_redirects=False
    )
    assert "/wan-verify" in response.location

    # Test signin
    logout(client)

    response = client.post("/wan-signin/not a token", json=dict())
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "API_ERROR"
    )
    # same w/o json
    response = client.post(
        "/wan-signin/not a token", data=dict(), follow_redirects=True
    )
    assert get_message("API_ERROR") in response.data
    response = client.post(
        "/wan-signin/not a token", data=dict(), follow_redirects=False
    )
    assert "/wan-signin" in response.location


@pytest.mark.settings(
    wan_register_template="custom_security/wan_register.html",
    wan_signin_template="custom_security/wan_signin.html",
    wan_verify_template="custom_security/wan_verify.html",
)
def test_wan_context_processors(client, app):
    @app.security.context_processor
    def default_ctx_processor():
        return {"global": "global"}

    @app.security.wan_register_context_processor
    def register_ctx():
        return {"foo": "register"}

    authenticate(client)

    response = client.get("wan-register")
    assert b"CUSTOM WAN REGISTER" in response.data
    assert b"global" in response.data
    assert b"register" in response.data

    response = client.post("wan-register", data=dict(name="matt@lp.com"))
    assert b"CUSTOM WAN REGISTER" in response.data
    assert b"global" in response.data
    assert b"register" in response.data
    logout(client)

    @app.security.wan_signin_context_processor
    def signin_ctx():
        return {"foo": "signin"}

    response = client.get("wan-signin")
    assert b"CUSTOM WAN SIGNIN" in response.data
    assert b"global" in response.data
    assert b"signin" in response.data

    response = client.post("wan-signin", data=dict(name="matt@lp.com"))
    assert b"CUSTOM WAN SIGNIN" in response.data
    assert b"global" in response.data
    assert b"signin" in response.data

    @app.security.wan_verify_context_processor
    def verify_ctx():
        return {"foo": "verify"}

    authenticate(client)
    response = client.get("wan-verify")
    assert b"CUSTOM WAN VERIFY" in response.data
    assert b"global" in response.data
    assert b"verify" in response.data

    response = client.post("wan-verify", data=dict(name="matt@lp.com"))
    assert b"CUSTOM WAN VERIFY" in response.data
    assert b"global" in response.data
    assert b"verify" in response.data


@pytest.mark.two_factor()
@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_alt_tf(app, client, get_message):
    # Use webauthn as primary and set up SMS as second factor
    authenticate(client)

    register_options, response_url = _register_start_json(client, usage="first")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200

    sms_sender = setup_tf_sms(client)
    logout(client)

    # sign in using webauthn key
    signin_options, response_url, _ = _signin_start_json(client, "matt@lp.com")
    response = client.post(
        response_url,
        json=dict(credential=json.dumps(SIGNIN_DATA1)),
    )
    assert response.status_code == 200
    assert response.json["response"]["tf_required"]

    code = sms_sender.messages[0].split()[-1]
    response = client.post("/tf-validate", json=dict(code=code))
    assert response.status_code == 200
    # verify logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200


@pytest.mark.two_factor()
@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_all_in_one(app, client, get_message):
    # Use a key that supports user_verification - we should be able to
    # use that alone.
    authenticate(client)
    register_options, response_url = _register_start_json(client, usage="first")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA_UV)))
    assert response.status_code == 200
    setup_tf_sms(client)

    logout(client)
    signin_options, response_url, rjson = _signin_start_json(client, "matt@lp.com")
    assert "user" not in rjson["response"]
    response = client.post(
        response_url, json=dict(credential=json.dumps(SIGNIN_DATA_UV))
    )
    assert response.json["response"]["user"]["email"] == "matt@lp.com"

    # verify actually logged in
    response = client.get("/profile", headers={"accept": "application/json"})
    assert response.status_code == 200


@pytest.mark.two_factor()
@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_all_in_one_not_allowed(app, client, get_message):
    # now test when we don't allow a key to satisfy both factors
    authenticate(client)
    register_options, response_url = _register_start_json(client, usage="first")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA_UV)))
    assert response.status_code == 200
    setup_tf_sms(client)
    logout(client)

    app.config["SECURITY_WAN_ALLOW_AS_MULTI_FACTOR"] = False
    signin_options, response_url, rjson = _signin_start_json(client, "matt@lp.com")
    assert "user" not in rjson["response"]

    response = client.post(
        response_url, json=dict(credential=json.dumps(SIGNIN_DATA_UV))
    )
    assert response.json["response"]["tf_required"]


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_reset(app, client):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    authenticate(client)
    register_options, response_url = _register_start_json(client)
    client.post(response_url, json=dict(credential=json.dumps(REG_DATA_UV)))

    response = client.get("/wan-register", headers=headers)
    active_creds = response.json["response"]["registered_credentials"]
    assert active_creds[0]["name"] == "testr1"

    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        app.security.datastore.webauthn_reset(user)
        app.security.datastore.commit()

    response = client.get("/wan-register", headers=headers)
    active_creds = response.json["response"]["registered_credentials"]
    assert len(active_creds) == 0


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_user_handle(app, client, get_message):
    """Test that we fail signin if user_handle doesn't match.
    Since we generated the SIGNIN_DATA_OH from view_scaffold - the user_handle
    has no way of matching.
    """
    authenticate(client)
    register_options, response_url = _register_start_json(client, usage="first")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA_UH)))
    assert response.status_code == 200

    # verify can't sign in
    logout(client)
    signin_options, response_url, _ = _signin_start_json(client, "matt@lp.com")
    response = client.post(
        response_url, json=dict(credential=json.dumps(SIGNIN_DATA_UH))
    )
    assert response.json["response"]["field_errors"]["credential"][0].encode(
        "utf-8"
    ) == get_message("WEBAUTHN_MISMATCH_USER_HANDLE")

    # Now change the user_handle both for the user and SIGNIN_DATA_UH
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        app.security.datastore.set_webauthn_user_handle(user)
        app.security.datastore.commit()

        b64_user_handle = (
            urlsafe_b64encode(user.fs_webauthn_user_handle.encode())
            .decode("utf-8")
            .replace("=", "")
        )
    upd_signin_data = copy.deepcopy(SIGNIN_DATA_UH)
    upd_signin_data["response"]["userHandle"] = b64_user_handle
    signin_options, response_url, _ = _signin_start_json(client, "matt@lp.com")
    response = client.post(
        response_url, json=dict(credential=json.dumps(upd_signin_data))
    )
    # verify actually logged in
    response = client.get("/profile", headers={"accept": "application/json"})
    assert response.status_code == 200


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_autogen_user_handle(app, client, get_message):
    # Test that is an existing user doesn't have a fs_webauthn_user_handle - it will
    # be generated.
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        user.fs_webauthn_user_handle = None
        app.security.datastore.put(user)
        app.security.datastore.commit()

    authenticate(client)
    register_options, response_url = _register_start_json(client, usage="first")
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        assert user.fs_webauthn_user_handle
        b64_user_handle = (
            urlsafe_b64encode(user.fs_webauthn_user_handle.encode())
            .decode("utf-8")
            .replace("=", "")
        )
        assert b64_user_handle == register_options["user"]["id"]


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_verify_json(app, client, get_message):
    # Test can re-authenticate using existing webauthn key.
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    authenticate(client)
    register_options, response_url = _register_start_json(client, usage="first")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200

    reset_fresh(client, app.config["SECURITY_FRESHNESS"])

    response = client.get("fresh", headers=headers)
    assert response.status_code == 401
    assert response.json["response"]["reauth_required"]
    assert response.json["response"]["has_webauthn_verify_credential"]

    response = client.get("wan-verify", headers=headers)
    assert response.status_code == 200

    response = client.post("wan-verify", json=dict())
    # default webauthn_utils will set userVerification to discouraged in the
    # case of verify.
    signin_options = response.json["response"]["credential_options"]
    assert signin_options["userVerification"] == "discouraged"

    response_url = f'wan-verify/{response.json["response"]["wan_state"]}'
    response = client.post(response_url, json=dict(credential=json.dumps(SIGNIN_DATA1)))
    assert response.status_code == 200

    response = client.get("fresh", headers=headers)
    assert response.status_code == 200


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_verify(app, client, get_message):
    # Test can re-authenticate using existing webauthn key.
    # Forms version - verify that the 'next' qparam is properly maintained during the
    # 2 part authentication.
    authenticate(client)
    register_options, response_url = _register_start(client, usage="first")
    response = client.post(
        response_url, data=dict(credential=json.dumps(REG_DATA1)), follow_redirects=True
    )
    assert response.status_code == 200
    assert b"testr1" in response.data

    old_paa = reset_fresh(client, app.config["SECURITY_FRESHNESS"])
    response = client.get("fresh")
    assert "/verify?next=http://localhost/fresh" in response.location
    signin_options, response_url = _signin_start(
        client, endpoint="wan-verify?next=/fresh"
    )

    response = client.post(
        response_url,
        data=dict(credential=json.dumps(SIGNIN_DATA1)),
        follow_redirects=False,
    )
    assert "/fresh" in response.location
    with client.session_transaction() as sess:
        assert sess["fs_paa"] > old_paa


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil, wan_signin_within="2 seconds")
def test_verify_timeout(app, client, get_message):
    authenticate(client)
    register_options, response_url = _register_start_json(client, name="testr3")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200

    app.security.wan_serializer = FakeSerializer(2.0)
    response = client.post("wan-verify", json=dict())
    response_url = f'wan-verify/{response.json["response"]["wan_state"]}'
    response = client.post(response_url, json=dict(credential=json.dumps(SIGNIN_DATA1)))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "WEBAUTHN_EXPIRED", within=app.config["SECURITY_WAN_SIGNIN_WITHIN"]
    )


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_verify_validate_error(app, client, get_message):
    authenticate(client)
    register_options, response_url = _register_start_json(client, name="testr3")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200

    response = client.post("wan-verify", json=dict())
    response_url = f'wan-verify/{response.json["response"]["wan_state"]}'
    # send wrong signin data
    response = client.post(
        response_url, json=dict(credential=json.dumps(SIGNIN_DATA_UH))
    )
    assert response.status_code == 400
    assert response.json["response"]["field_errors"]["credential"][0].encode(
        "utf-8"
    ) == get_message("WEBAUTHN_UNKNOWN_CREDENTIAL_ID")

    # same thing - with forms - this should redirect to wan-verify and flash a message
    with capture_flashes() as flashes:
        response = client.post(
            response_url,
            data=dict(credential=json.dumps(SIGNIN_DATA_UH)),
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "/wan-verify" in response.location
    assert flashes[0]["category"] == "error"
    assert flashes[0]["message"].encode("utf-8") == get_message(
        "WEBAUTHN_UNKNOWN_CREDENTIAL_ID"
    )


@pytest.mark.settings(wan_allow_as_verify=None)
def test_no_verify(app, client):
    authenticate(client)
    response = client.get("/wan-verify")
    assert response.status_code == 404


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_verify_usage_any_json(app, client, get_message):
    # Test the WAN_ALLOW_AS_VERIFY config.
    # Make sure only allowed credentials show up as options
    # Make sure if we use a disallowed credential, we get an error.
    keys = reg_2_keys(client)

    # Default WAN_ALLOW_AS_VERIFY is ["first", "secondary"]
    response = client.post("wan-verify", json=dict())
    response_url = f'wan-verify/{response.json["response"]["wan_state"]}'
    allow_credentials = response.json["response"]["credential_options"][
        "allowCredentials"
    ]
    assert len(allow_credentials) == 2

    # make sure can sign in with either
    response = client.post(
        response_url, json=dict(credential=json.dumps(keys["first"]["signin"]))
    )
    assert response.status_code == 200
    response = client.post(
        response_url, json=dict(credential=json.dumps(keys["secondary"]["signin"]))
    )
    assert response.status_code == 200


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil, wan_allow_as_verify="first")
def test_verify_usage_first_json(app, client, get_message):
    # Test the WAN_ALLOW_AS_VERIFY config.
    # Make sure only allowed credentials show up as options
    # Make sure if we use a disallowed credential, we get an error.
    keys = reg_2_keys(client)

    response = client.post("wan-verify", json=dict())
    response_url = f'wan-verify/{response.json["response"]["wan_state"]}'
    allow_credentials = response.json["response"]["credential_options"][
        "allowCredentials"
    ]
    assert len(allow_credentials) == 1
    assert allow_credentials[0]["id"] == keys["first"]["id"]

    # make sure can sign in with just "first"
    response = client.post(
        response_url, json=dict(credential=json.dumps(keys["first"]["signin"]))
    )
    assert response.status_code == 200
    # but not "secondary"
    response = client.post(
        response_url, json=dict(credential=json.dumps(keys["secondary"]["signin"]))
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "WEBAUTHN_CREDENTIAL_WRONG_USAGE"
    )


@pytest.mark.settings(
    webauthn_util_cls=HackWebauthnUtil, wan_allow_as_verify="secondary"
)
def test_verify_usage_secondary_json(app, client, get_message):
    # Test the WAN_ALLOW_AS_VERIFY config.
    # Make sure only allowed credentials show up as options
    # Make sure if we use a disallowed credential, we get an error.
    keys = reg_2_keys(client)

    response = client.post("wan-verify", json=dict())
    response_url = f'wan-verify/{response.json["response"]["wan_state"]}'
    allow_credentials = response.json["response"]["credential_options"][
        "allowCredentials"
    ]
    assert len(allow_credentials) == 1
    assert allow_credentials[0]["id"] == keys["secondary"]["id"]

    # make sure can sign in with just "secondary"
    response = client.post(
        response_url, json=dict(credential=json.dumps(keys["first"]["signin"]))
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "WEBAUTHN_CREDENTIAL_WRONG_USAGE"
    )
    response = client.post(
        response_url, json=dict(credential=json.dumps(keys["secondary"]["signin"]))
    )
    assert response.status_code == 200


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_remember_token(client):
    # test that remember token properly set on primary authn with webauthn
    authenticate(client)
    register_options, response_url = _register_start_json(
        client, name="testr3", usage="first"
    )
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200
    logout(client)

    assert not client.get_cookie("remember_token")

    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    response = client.post(
        "wan-signin", headers=headers, json=dict(identity="matt@lp.com", remember=True)
    )
    response_url = f'wan-signin/{response.json["response"]["wan_state"]}'
    assert response.json["response"]["remember"]

    response = client.post(
        response_url,
        json=dict(credential=json.dumps(SIGNIN_DATA1), remember=True),
    )
    assert client.get_cookie("remember_token")
    client.delete_cookie("session")
    response = client.get("/profile")
    assert b"profile" in response.data


@pytest.mark.two_factor()
@pytest.mark.unified_signin()
@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_remember_token_tf(client):
    # test that remember token properly set after secondary authn with webauthn
    authenticate(client)
    register_options, response_url = _register_start_json(client, name="testr3")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200
    logout(client)

    assert not client.get_cookie("remember_token")

    # login again - should require MFA
    response = client.post(
        "/us-signin",
        json=dict(identity="matt@lp.com", passcode="password", remember=True),
    )
    assert response.status_code == 200
    assert response.json["response"]["tf_method"] == "webauthn"
    assert response.json["response"]["tf_required"]
    with client.session_transaction() as session:
        assert session["tf_remember_login"]

    signin_options, response_url, _ = _signin_start_json(client, "matt@lp.com")
    response = client.post(
        response_url,
        json=dict(credential=json.dumps(SIGNIN_DATA1), remember=True),
    )
    assert client.get_cookie("remember_token")
    client.delete_cookie("session")
    response = client.get("/profile")
    assert b"profile" in response.data


@pytest.mark.settings(
    webauthn_util_cls=HackWebauthnUtil,
    wan_post_register_view="/post_register",
)
def test_post_register_redirect(app, client, get_message):
    authenticate(client)

    register_options, response_url = _register_start_json(client, name="testr3")
    response = client.post(
        response_url,
        data=dict(credential=json.dumps(REG_DATA1)),
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/post_register" in response.location


class MyWebauthnUtil(HackWebauthnUtil):
    def user_verification(self, user, usage):
        from webauthn.helpers.structs import UserVerificationRequirement

        return UserVerificationRequirement.REQUIRED


@pytest.mark.two_factor()
@pytest.mark.unified_signin()
@pytest.mark.settings(webauthn_util_cls=MyWebauthnUtil)
def test_uv_required(client):
    # Override WebauthnUtils to require user-verification on signin.
    keys = reg_2_keys(client)
    logout(client)

    # log back in - should require MFA.
    response = client.post(
        "/us-signin",
        json=dict(identity="matt@lp.com", passcode="password", remember=True),
    )
    assert response.status_code == 200
    assert response.json["response"]["tf_required"]

    # since we always REQUIRE user_verification in our WebauthUtil this should fail
    signin_options, response_url, _ = _signin_start_json(client, "")
    response = client.post(
        response_url,
        json=dict(credential=json.dumps(keys["secondary"]["signin"])),
    )
    assert response.status_code == 400
    assert (
        "User verification is required"
        in response.json["response"]["field_errors"]["credential"][0]
    )

    logout(client)

    # Try signing in with 'first' WebAuthn key - this DOES have UV set so should work.
    signin_options, response_url, _ = _signin_start_json(client, "")
    response = client.post(
        response_url,
        json=dict(credential=json.dumps(keys["first"]["signin"])),
    )
    assert response.status_code == 200
    assert response.json["response"]["user"]["email"] == "matt@lp.com"


@pytest.mark.settings(
    multi_factor_recovery_codes=True, webauthn_util_cls=HackWebauthnUtil
)
def test_mf(client):
    # Test using recovery codes in-liu of a webauthn second factor
    # Note that we are allowed to generate recovery codes even if we don't yet have
    # an established 2nd factor
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    authenticate(client)
    response = client.post("/mf-recovery-codes", headers=headers)
    codes = response.json["response"]["recovery_codes"]
    assert len(codes) == 5

    # setup webauthn
    register_options, response_url = _register_start_json(client, name="testr3")
    response = client.post(response_url, json=dict(credential=json.dumps(REG_DATA1)))
    assert response.status_code == 200
    logout(client)

    response = client.post(
        "/login", json=dict(email="matt@lp.com", password="password")
    )
    assert response.status_code == 200
    assert response.json["response"]["tf_required"]

    # oh no - we forgot our webauthn key
    """ Right now tf-rescue is part of TWO_FACTOR - not WEBAUTHN
    response = client.get("/tf-rescue", headers=headers)
    options = response.json["response"]["recovery_options"]
    assert "recovery_code" in options.keys()
    assert "/mf-recovery" in options["recovery_code"]
    """

    response = client.post(
        "/mf-recovery", data=dict(code=codes[0]), follow_redirects=True
    )
    assert response.status_code == 200

    # verify actually logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200


@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil, url_prefix="/auth")
def test_login_next(app, client, get_message):
    # Test that ?next=/xx is propagated through login/wan-signin templates as well as
    # views.
    # Also - use a different blueprint prefix - we rarely test that....
    authenticate(client, endpoint="/auth/login")
    register_options, response_url = _register_start(
        client, name="testr3", usage="first", endpoint="/auth/wan-register"
    )
    response = client.post(
        response_url, data=dict(credential=json.dumps(REG_DATA1)), follow_redirects=True
    )
    assert response.status_code == 200
    assert get_message("WEBAUTHN_REGISTER_SUCCESSFUL", name="testr3") in response.data
    logout(client, endpoint="/auth/logout")

    response = client.get("profile", follow_redirects=True)
    assert "?next=/profile" in response.request.url
    # pull webauthn form action out of login_form - should have ?next=...
    webauthn_url = get_form_action(response, 1)

    signin_options, response_url = _signin_start(
        client, "matt@lp.com", endpoint=webauthn_url
    )
    response = client.post(
        response_url,
        data=dict(credential=json.dumps(SIGNIN_DATA1)),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Profile Page" in response.data
