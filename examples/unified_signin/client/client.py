"""
Copyright 2020-2021 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.

This relies on session/session cookie for continued authentication.
It assumes server is set up to send a CSRF cookie.

We assume server doesn't require CSRF for unauthenticated endpoints.

Note that we have to manually take the CSRF cookie and send it as a header.
For many javascript http clients - they do this as part of default configuration.

"""

import logging
import random
import re

import requests

logger = logging.getLogger(__name__)


class ApiException(Exception):
    def __init__(self, msg, status_code):
        if isinstance(msg, list):
            self.msg = msg
        else:
            self.msg = [msg]
        self.status_code = status_code

    def get_msgs(self):
        return ", ".join(self.msg)


def check_error(resp):
    # look for errors from Flask-Security API and throw exception with info
    jresp = resp.json()
    rdata = jresp.get("response")
    if not rdata:
        raise ApiException("Bad Api Response", resp.status_code)
    if "error" in rdata:
        raise ApiException(rdata["error"], resp.status_code)
    if "errors" in rdata:
        # these are form errors a dict of form label: [list of errors]
        msgs = []
        for label, emsgs in rdata["errors"].items():
            msgs.extend([f"{label}-{msg}" for msg in emsgs])
        raise ApiException(msgs, resp.status_code)
    if resp.status_code >= 400:
        raise ApiException("Error status w/o response", resp.status_code)
    return None


def register(server_url, session, email, password):
    # Register new email with password
    # Use the backdoor to grab confirmation email and confirm.

    resp = session.post(
        f"{server_url}/register",
        json={"email": email, "password": password},
    )
    check_error(resp)

    resp = session.get(f"{server_url}/api/popmail")
    if resp.status_code != 200:
        raise ApiException("popmail error", resp.status_code)

    jbody = resp.json()

    # Parse for link
    matcher = re.match(
        r".*(http://[^\s*]*).*", jbody["mail"], re.IGNORECASE | re.DOTALL
    )
    magic_link = matcher.group(1)

    # Note this simulates someone clicking on the email link - no point in claiming
    # this is json.
    resp = session.get(magic_link, allow_redirects=False)
    assert resp.status_code == 302


def ussetup(server_url, session, password, phone):
    # unified sign in - setup sms with a phone number
    # Use the backdoor to grab verification SMS.

    csrf_token = session.cookies["XSRF-TOKEN"]
    resp = session.post(
        f"{server_url}/us-setup",
        json={"chosen_method": "us_phone_number", "phone": phone},
        headers={"X-XSRF-Token": csrf_token},
    )

    # this should be a 401 reauth required
    assert resp.status_code == 401
    jbody = resp.json()
    assert jbody["response"]["reauth_required"]

    # re-verify
    resp = session.post(
        f"{server_url}/us-verify",
        json={"passcode": password},
        headers={"X-XSRF-Token": csrf_token},
    )
    assert resp.status_code == 200

    # try again
    resp = session.post(
        f"{server_url}/us-setup",
        json={"chosen_method": "sms", "phone": phone},
        headers={"X-XSRF-Token": csrf_token},
    )
    check_error(resp)
    jbody = resp.json()
    state = jbody["response"]["state"]

    resp = session.get(f"{server_url}/api/popsms")
    if resp.status_code != 200:
        raise ApiException("popsms error", resp.status_code)

    jbody = resp.json()
    code = jbody["sms"].split()[-1].strip(".")
    resp = session.post(
        f"{server_url}/us-setup/{state}",
        json={"passcode": code},
        headers={"X-XSRF-Token": csrf_token},
    )
    check_error(resp)


def sms_signin(server_url, session, username, phone):
    # Sign in using SMS code.
    session.post(
        f"{server_url}/us-signin/send-code",
        json={"identity": username, "chosen_method": "sms"},
    )

    # Fetch code via test API
    resp = session.get(f"{server_url}/api/popsms")
    if resp.status_code != 200:
        raise ApiException("popsms error", resp.status_code)

    jbody = resp.json()
    code = jbody["sms"].split()[-1].strip(".")
    resp = session.post(
        f"{server_url}/us-signin",
        json={"identity": username, "passcode": code},
    )
    check_error(resp)


def runit():
    session = requests.session()
    session.headers.update(
        {"Accept": "application/json", "Content-Type": "application/json"}
    )
    server_url = "http://localhost:5002"

    try:
        username = f"example{str(random.randint(0, 100000))}@me.com"
        mypassword = "a good easy question"
        myphone = "+16505551212"

        # New user - register and confirm
        register(
            server_url,
            session,
            username,
            mypassword,
        )
        # verify confirmed and logged in
        resp = session.get(f"{server_url}/api/health")
        assert resp.status_code == 200
        jresp = resp.json()
        assert jresp["secret"] == "lush oranges"

        # Now us-setup to setup a phone number
        ussetup(server_url, session, mypassword, myphone)

        # Verify can sign in with SMS
        session.post(f"{server_url}/logout")
        sms_signin(server_url, session, username, myphone)

        # verify logged in
        resp = session.get(f"{server_url}/api/health")
        assert resp.status_code == 200
        jresp = resp.json()
        assert jresp["secret"] == "lush oranges"
        logging.info("Success")

    except ApiException as exc:
        logging.error(f"{exc.get_msgs()}")


if __name__ == "__main__":
    # Run through simple sequence
    logging.basicConfig(level=logging.INFO)
    runit()
