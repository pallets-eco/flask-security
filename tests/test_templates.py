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
    get_form_input_value,
    reset_fresh,
    setup_tf_sms,
)
from tests.test_webauthn import HackWebauthnUtil, reg_first_key


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
    return check_template_rdata(name, r, t.data)


def check_template_rdata(name, r, rdata):
    vout = r.post("https://validator.w3.org/nu/?out=json", rdata)
    if vout.status_code == 429:
        # we got rate limited try again
        sleep(2.0)
        vout = r.post("https://validator.w3.org/nu/?out=json", rdata)
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
@pytest.mark.oauth()
@pytest.mark.username_recovery()
@pytest.mark.unified_signin()
@pytest.mark.webauthn(webauthn_util_cls=HackWebauthnUtil)
@pytest.mark.two_factor()
@pytest.mark.settings(
    multi_factor_recovery_codes=True,
    oauth_enable=True,
)
@pytest.mark.csrf()
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
    # TWO_FACTOR_RESCUE has an issue with the RadioField
    # TWO_FACTOR_SELECT needs special setup

    authenticate(client, csrf=True)
    response = client.get("/change")
    csrf_token = get_form_input_value(response, "csrf_token")
    reg_first_key(client, csrf_token=csrf_token)

    logout(client)

    terrors = dict()
    for t in [u for u in unauth_urls if u in totry]:
        terrors[t] = check_template(app.config[f"SECURITY_{t}_URL"], client, rsession)

    authenticate(client, csrf=True)
    for t in [u for u in auth_urls if u in totry]:
        if t == "US_SETUP":
            response = client.get("/us-setup")
            csrf_token = get_form_input_value(response, "csrf_token")
            response = client.post(
                "us-setup",
                data=dict(chosen_method="authenticator", csrf_token=csrf_token),
            )
            terrors[t] = check_template_rdata("US_SETUP", rsession, response.data)
            continue
        if t == "TWO_FACTOR_SETUP":
            response = client.get("/tf-setup")
            csrf_token = get_form_input_value(response, "csrf_token")
            response = client.post(
                "tf-setup",
                data=dict(setup="authenticator", csrf_token=csrf_token),
            )
            terrors[t] = check_template_rdata(
                "TWO_FACTOR_SETUP", rsession, response.data
            )
            continue
        elif t == "US_VERIFY" or t == "VERIFY":
            reset_fresh(client, app.config["SECURITY_FRESHNESS"])

        terrors[t] = check_template(app.config[f"SECURITY_{t}_URL"], client, rsession)

    print(f"Validated: {totry}")
    errors = {k: v for k, v in terrors.items() if v}
    assert not any(errors), errors


@pytest.mark.confirmable()
@pytest.mark.csrf()
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
@pytest.mark.csrf()
def test_valid_html_recover(app, client):
    rsession = requests.session()
    rsession.headers.update({"Content-Type": "text/html; charset=utf-8"})
    # since we get rate limited - use external pytest option to specify
    totry = app.config.get("TEMPLATES", "").split(",")
    if "RESET" in totry:
        print(f"Validated: {totry}")
        with capture_reset_password_requests() as resets:
            response = client.get("/reset")
            csrf_token = get_form_input_value(response, "csrf_token")
            client.post("/reset", data=dict(email="joe@lp.com", csrf_token=csrf_token))
        token = resets[0]["token"]
        terrors = check_template(
            f'{app.config[f"SECURITY_RESET_URL"]}/{token}', client, rsession
        )
        assert not terrors


@pytest.mark.two_factor()
@pytest.mark.csrf()
def test_valid_html_rescue(app, client):
    rsession = requests.session()
    rsession.headers.update({"Content-Type": "text/html; charset=utf-8"})
    # since we get rate limited - use external pytest option to specify
    totry = app.config.get("TEMPLATES", "").split(",")
    if "TWO_FACTOR_RESCUE" in totry:
        authenticate(client, csrf=True)
        response = client.get("/tf-setup")
        csrf_token = get_form_input_value(response, "csrf_token")
        setup_tf_sms(client, csrf_token=csrf_token)
        logout(client)
        authenticate(client, csrf=True)
        print(f"Validated: {totry}")
        terrors = check_template(
            app.config["SECURITY_TWO_FACTOR_RESCUE_URL"], client, rsession
        )
        assert not terrors
