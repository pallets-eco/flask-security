"""
test_templates
~~~~~~~~~~

Test templates to be W3C valid

:copyright: (c) 2025-2025 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.

Note that the validator definitely rate-limits us - so we don't just run
them all.

To run a test pass templates="RESET,LOGIN" on the command line.
"""

from time import sleep

import pytest
import requests

from tests.test_utils import (
    authenticate,
    logout,
    capture_reset_password_requests,
    reset_fresh,
    setup_tf_sms,
)


def check_message(msgs, mtype="error"):
    # list of JSON messages from validator
    errors = []
    for msg in msgs:
        if msg["type"] == mtype:
            errors.append(msg["message"])
    return errors


def check_template(name, client, r):
    # returns list of validation errors
    t = client.get(name)
    if t.status_code != 200:
        return [f"{name} error {t.status_code}"]
    vout = r.post("https://validator.w3.org/nu/?out=json", t.data)
    if vout.status_code == 429:
        # we got rate limited try again
        sleep(2.0)
        vout = r.post("https://validator.w3.org/nu/?out=json", t.data)
        if vout.status_code != 200:
            return [f"{name} API error {vout.status_code}"]
    if vout.status_code != 200:
        return [f"{name} API error {vout.status_code}"]
    return check_message(vout.json()["messages"])


@pytest.mark.registerable()
@pytest.mark.recoverable()
@pytest.mark.changeable()
@pytest.mark.change_email()
@pytest.mark.change_username()
@pytest.mark.username_recovery()
@pytest.mark.unified_signin()
@pytest.mark.webauthn()
@pytest.mark.two_factor()
@pytest.mark.settings(multi_factor_recovery_codes=True)
def test_valid_html(app, client):
    # since we get rate limited - use external pytest option to specify
    totry = app.config.get("TEMPLATES", "").split(",")
    rsession = requests.session()
    rsession.headers.update({"Content-Type": "text/html; charset=utf-8"})

    unauth_urls = [
        "LOGIN",
        "REGISTER",
        "RESET",
        "US_SIGNIN",
        "USERNAME_RECOVERY",
        "WAN_SIGNIN",
    ]
    auth_urls = [
        "CHANGE",
        "CHANGE_USERNAME",
        "CHANGE_EMAIL",
        "MULTI_FACTOR_RECOVERY_CODES",
        "TWO_FACTOR_SETUP",
        "US_SETUP",
        "US_VERIFY",
        "WAN_REGISTER",
        "WAN_VERIFY",
    ]

    # MULTI_FACTOR_RECOVERY requires tf-setup and login/password
    # TWO_FACTOR_RESCUE has an issue with the RadioField - possibly because we
    # change it after instantiation???
    # TWO_FACTOR_SELECT needs special setup
    authenticate(client)
    logout(client)

    terrors = dict()
    for t in [u for u in unauth_urls if u in totry]:
        terrors[t] = check_template(app.config[f"SECURITY_{t}_URL"], client, rsession)

    authenticate(client)
    for t in [u for u in auth_urls if u in totry]:
        terrors[t] = check_template(app.config[f"SECURITY_{t}_URL"], client, rsession)

    if "VERIFY" in totry:
        reset_fresh(client, app.config["SECURITY_FRESHNESS"])
        terrors["VERIFY"] = check_template(
            app.config["SECURITY_VERIFY_URL"], client, rsession
        )

    print(f"Validated: {totry}")
    errors = {k: v for k, v in terrors.items() if v}
    assert not any(errors), errors


@pytest.mark.confirmable()
def test_valid_html_confirm(app, client):
    rsession = requests.session()
    rsession.headers.update({"Content-Type": "text/html; charset=utf-8"})
    # since we get rate limited - use external pytest option to specify
    totry = app.config.get("TEMPLATES", "").split(",")
    if "CONFIRM" in totry:
        print(f"Validated: {totry}")
        terrors = check_template(app.config["SECURITY_CONFIRM_URL"], client, rsession)
        assert not terrors


@pytest.mark.recoverable()
def test_valid_html_recover(app, client):
    rsession = requests.session()
    rsession.headers.update({"Content-Type": "text/html; charset=utf-8"})
    # since we get rate limited - use external pytest option to specify
    totry = app.config.get("TEMPLATES", "").split(",")
    if "RESET" in totry:
        print(f"Validated: {totry}")
        with capture_reset_password_requests() as resets:
            client.post("/reset", data=dict(email="joe@lp.com"))
        token = resets[0]["token"]
        terrors = check_template(
            f'{app.config[f"SECURITY_RESET_URL"]}/{token}', client, rsession
        )
        assert not terrors


@pytest.mark.two_factor()
def test_valid_html_rescue(app, client):
    rsession = requests.session()
    rsession.headers.update({"Content-Type": "text/html; charset=utf-8"})
    # since we get rate limited - use external pytest option to specify
    totry = app.config.get("TEMPLATES", "").split(",")
    if "TWO_FACTOR_RESCUE" in totry:
        authenticate(client)
        setup_tf_sms(client)
        logout(client)
        authenticate(client)
        print(f"Validated: {totry}")
        terrors = check_template(
            app.config["SECURITY_TWO_FACTOR_RESCUE_URL"], client, rsession
        )
        assert not terrors
