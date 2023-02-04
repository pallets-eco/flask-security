"""
    test_recovery_codes
    ~~~~~~~~~~~~~~~~~

    recovery code tests

    :copyright: (c) 2022-2023 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import re

import pytest

from tests.test_two_factor import tf_authenticate
from tests.test_utils import (
    authenticate,
    logout,
    reset_fresh,
    setup_tf_sms,
)

pytestmark = pytest.mark.two_factor()


@pytest.mark.settings(multi_factor_recovery_codes=True)
def test_rc_json(app, client, get_message):
    # Test recovery codes
    # gal has two-factor already setup for 'sms'
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    tf_authenticate(app, client)

    response = client.get("/mf-recovery-codes", headers=headers)
    assert response.status_code == 200
    codes = response.json["response"]["recovery_codes"]
    assert len(codes) == 0

    response = client.post("/mf-recovery-codes", headers=headers)
    codes = response.json["response"]["recovery_codes"]
    assert len(codes) == 5

    response = client.get("/mf-recovery-codes", headers=headers)
    recodes = response.json["response"]["recovery_codes"]
    assert len(recodes) == 5 and codes[0] == recodes[0]

    response = client.get("/mf-recovery-codes", headers=headers)
    assert response.status_code == 200
    assert not hasattr(response.json["response"], "recovery_codes")

    # endpoint is for unauthenticated only
    response = client.post("/mf-recovery", json=dict(code=codes[0]))
    assert response.status_code == 400
    logout(client)

    response = client.post("/login", json=dict(email="gal@lp.com", password="password"))
    assert response.json["response"]["tf_required"]

    response = client.post("/mf-recovery", json=dict(code=codes[0]))
    assert response.status_code == 200

    # verify actually logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200

    # logout and try again - first code shouldn't work again
    logout(client)
    response = client.post("/login", json=dict(email="gal@lp.com", password="password"))
    assert response.json["response"]["tf_required"]

    response = client.post("/mf-recovery", json=dict(code=codes[0]))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "INVALID_RECOVERY_CODE"
    )
    response = client.post("/mf-recovery", json=dict(code=codes[1]))
    assert response.status_code == 200


@pytest.mark.settings(multi_factor_recovery_codes=True)
def test_rc(app, client, get_message):
    # Test recovery codes
    # gal has two-factor already setup for 'sms'
    tf_authenticate(app, client)

    response = client.get("/mf-recovery-codes?show_codes=hi")
    assert response.status_code == 200
    assert get_message("NO_RECOVERY_CODES_SETUP") in response.data

    response = client.post("/mf-recovery-codes")
    rd = response.data.decode("utf-8")
    codes = re.findall(r"[a-f,\d]{4}-[a-f,\d]{4}-[a-f,\d]{4}", rd)
    assert len(codes) == 5

    response = client.get("/mf-recovery-codes?show_codes=hi")
    assert response.status_code == 200
    assert b"Recovery Codes" in response.data
    rd = response.data.decode("utf-8")
    codes = re.findall(r"[a-f,\d]{4}-[a-f,\d]{4}-[a-f,\d]{4}", rd)
    assert len(codes) == 5

    # endpoint is for unauthenticated only
    response = client.post(
        "/mf-recovery", data=dict(code=codes[0]), follow_redirects=False
    )
    assert response.status_code == 302
    logout(client)

    response = client.post("/login", json=dict(email="gal@lp.com", password="password"))
    assert response.json["response"]["tf_required"]

    response = client.post(
        "/mf-recovery", data=dict(code=codes[0]), follow_redirects=True
    )
    assert response.status_code == 200

    # verify actually logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200

    # logout and try again - first code shouldn't work again
    logout(client)
    response = client.post("/login", data=dict(email="gal@lp.com", password="password"))

    response = client.post("/mf-recovery", data=dict(code=codes[0]))
    assert get_message("INVALID_RECOVERY_CODE") in response.data
    response = client.post(
        "/mf-recovery", data=dict(code=codes[1]), follow_redirects=True
    )
    assert response.status_code == 200
    # verify actually logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200


@pytest.mark.settings(multi_factor_recovery_codes=True)
def test_rc_reset(app, client, get_message):
    # test that reset_user_access, removes recovery codes
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    tf_authenticate(app, client)

    response = client.post("/mf-recovery-codes", headers=headers)
    codes = response.json["response"]["recovery_codes"]
    assert len(codes) == 5

    with app.app_context():
        user = app.security.datastore.find_user(email="gal@lp.com")
        app.security.datastore.reset_user_access(user)
        app.security.datastore.commit()

    client.post("/login", json=dict(email="gal@lp.com", password="password"))
    response = client.get("/mf-recovery-codes", headers=headers)
    codes = response.json["response"]["recovery_codes"]
    assert len(codes) == 0


@pytest.mark.settings(multi_factor_recovery_codes=True, url_prefix="/api")
def test_rc_bad_state(app, client, get_message):
    response = client.post("/api/mf-recovery", json=dict(code="hi"))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf=8") == get_message(
        "TWO_FACTOR_PERMISSION_DENIED"
    )

    response = client.post(
        "/api/mf-recovery", data=dict(code="hi"), follow_redirects=False
    )
    assert response.status_code == 302
    assert "/api/login" in response.location


@pytest.mark.settings(multi_factor_recovery_codes=True)
def test_rc_rescue(app, client, get_message):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    tf_authenticate(app, client)

    response = client.post("/mf-recovery-codes", headers=headers)
    codes = response.json["response"]["recovery_codes"]
    assert len(codes) == 5
    logout(client)

    data = dict(email="gal@lp.com", password="password")
    response = client.post("/login", json=data)
    assert response.json["response"]["tf_required"]

    response = client.get("/tf-rescue")
    assert b"Use previously downloaded recovery code" in response.data

    response = client.get("/tf-rescue", headers=headers)
    options = response.json["response"]["recovery_options"]
    assert "recovery_code" in options.keys()
    assert "/mf-recovery" in options["recovery_code"]

    response = client.post(
        "/tf-rescue", data=dict(help_setup="recovery_code"), follow_redirects=False
    )
    assert "/mf-recovery" in response.location


@pytest.mark.settings(multi_factor_recovery_codes=True)
def test_fresh(app, client):
    # Make sure fetching recovery codes is protected with a freshness check.
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    authenticate(client)
    response = client.post("/mf-recovery-codes", headers=headers)
    codes = response.json["response"]["recovery_codes"]
    assert len(codes) == 5

    reset_fresh(client, app.config["SECURITY_FRESHNESS"])
    response = client.post("/mf-recovery-codes", headers=headers)
    assert response.status_code == 401
    assert response.json["response"]["reauth_required"]

    response = client.post("/verify", json=dict(password="password"))
    assert response.status_code == 200

    response = client.post("/mf-recovery-codes", headers=headers)
    codes = response.json["response"]["recovery_codes"]
    assert len(codes) == 5


@pytest.mark.settings(
    multi_factor_recovery_codes=True,
    multi_factor_recovery_codes_keys=[b"6_WhDTwI1RKJ3_ra9nADCBQbrRywlA88psGsq21xcsU="],
)
def test_rc_json_encrypted(app, client, get_message):
    # Test recovery codes with encryption option
    # gal has two-factor already setup for 'sms'
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    tf_authenticate(app, client)

    response = client.post("/mf-recovery-codes", headers=headers)
    codes = response.json["response"]["recovery_codes"]
    assert len(codes) == 5

    # endpoint is for unauthenticated only
    response = client.post("/mf-recovery", json=dict(code=codes[0]))
    assert response.status_code == 400
    logout(client)

    response = client.post("/login", json=dict(email="gal@lp.com", password="password"))
    assert response.json["response"]["tf_required"]

    response = client.post("/mf-recovery", json=dict(code=codes[0]))
    assert response.status_code == 200

    # verify actually logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200

    # logout and try again - first code shouldn't work again
    logout(client)
    response = client.post("/login", json=dict(email="gal@lp.com", password="password"))
    assert response.json["response"]["tf_required"]

    response = client.post("/mf-recovery", json=dict(code=codes[0]))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "INVALID_RECOVERY_CODE"
    )
    response = client.post("/mf-recovery", json=dict(code=codes[1]))
    assert response.status_code == 200

    # make sure DB actually has encrypted codes!
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="gal@lp.com")
        codes = user.mf_recovery_codes
        assert len(codes) == 3
        assert len(codes[0]) == 100


@pytest.mark.settings(
    multi_factor_recovery_codes=True,
    multi_factor_recovery_codes_keys=[b"6_WhDTwI1RKJ3_ra9nADCBQbrRywlA88psGsq21xcsU="],
)
def test_rc_json_encrypted_multi(app, client, get_message):
    # Test recovery codes with encryption option and multiple keys
    # gal has two-factor already setup for 'sms'
    from cryptography.fernet import Fernet

    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    tf_authenticate(app, client)

    response = client.post("/mf-recovery-codes", headers=headers)
    codes = response.json["response"]["recovery_codes"]
    assert len(codes) == 5
    logout(client)

    response = client.post("/login", json=dict(email="gal@lp.com", password="password"))
    assert response.json["response"]["tf_required"]

    response = client.post("/mf-recovery", json=dict(code=codes[0]))
    assert response.status_code == 200

    # verify actually logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200
    logout(client)

    # add a new key to cryptor and verify old code still works
    key2 = Fernet.generate_key()
    newkeys = [key2, b"6_WhDTwI1RKJ3_ra9nADCBQbrRywlA88psGsq21xcsU="]
    app.security._mf_recovery_codes_util.setup_cryptor(newkeys)

    response = client.post("/login", json=dict(email="gal@lp.com", password="password"))
    assert response.json["response"]["tf_required"]
    response = client.post("/mf-recovery", json=dict(code=codes[1]))
    assert response.status_code == 200
    logout(client)

    # creat codes for new user - this should use the new primary key.
    response = client.post(
        "/login", json=dict(email="matt@lp.com", password="password")
    )
    setup_tf_sms(client)
    response = client.post("/mf-recovery-codes", headers=headers)
    matt_codes = response.json["response"]["recovery_codes"]
    logout(client)

    # Now remove older key and codes for gal@lp.com shouldn't work
    app.security._mf_recovery_codes_util.setup_cryptor([key2])
    response = client.post("/login", json=dict(email="gal@lp.com", password="password"))
    assert response.json["response"]["tf_required"]
    response = client.post("/mf-recovery", json=dict(code=codes[2]))
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "INVALID_RECOVERY_CODE"
    )

    # matts codes should work
    response = client.post(
        "/login", json=dict(email="matt@lp.com", password="password")
    )
    assert response.json["response"]["tf_required"]
    response = client.post("/mf-recovery", json=dict(code=matt_codes[0]))
    assert response.status_code == 200
