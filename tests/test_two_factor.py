"""
    test_two_factor
    ~~~~~~~~~~~~~~~~~

    two_factor tests

    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from unittest.mock import Mock

import pytest
from flask_principal import identity_changed
from flask_security import (
    SQLAlchemyUserDatastore,
    SmsSenderFactory,
    reset_password_instructions_sent,
)
from flask_security.utils import capture_flashes
from tests.test_utils import (
    SmsBadSender,
    SmsTestSender,
    authenticate,
    get_session,
    logout,
)

pytestmark = pytest.mark.two_factor()


SmsSenderFactory.senders["test"] = SmsTestSender
SmsSenderFactory.senders["bad"] = SmsBadSender


class TestMail:
    def __init__(self):
        self.count = 0
        self.msg = None

    def send(self, msg):
        self.msg = msg
        self.count += 1


def tf_authenticate(app, client, validate=True):
    """ Login/Authenticate using two factor.
    This is the equivalent of utils:authenticate
    """
    prev_sms = app.config["SECURITY_SMS_SERVICE"]
    app.config["SECURITY_SMS_SERVICE"] = "test"
    sms_sender = SmsSenderFactory.createSender("test")
    json_data = dict(email="gal@lp.com", password="password")
    response = client.post(
        "/login", json=json_data, headers={"Content-Type": "application/json"}
    )
    assert b'"code": 200' in response.data
    app.config["SECURITY_SMS_SERVICE"] = prev_sms

    if validate:
        code = sms_sender.messages[0].split()[-1]
        response = client.post(
            "/tf-validate", data=dict(code=code), follow_redirects=True
        )
        assert response.status_code == 200


def tf_in_session(session):
    return any(
        k in session
        for k in [
            "tf_state",
            "tf_primary_method",
            "tf_user_id",
            "tf_confirmed",
            "tf_remember_login",
            "tf_totp_secret",
        ]
    )


@pytest.mark.settings(two_factor_required=True)
def test_two_factor_two_factor_setup_anonymous(app, client, get_message):

    # trying to pick method without doing earlier stage
    data = dict(setup="email")

    with capture_flashes() as flashes:
        response = client.post("/tf-setup", data=data)
        assert response.status_code == 302
    assert flashes[0]["category"] == "error"
    assert flashes[0]["message"].encode("utf-8") == get_message(
        "TWO_FACTOR_PERMISSION_DENIED"
    )


@pytest.mark.settings(two_factor_required=True)
def test_two_factor_flag(app, client):
    # trying to verify code without going through two-factor
    # first login function
    wrong_code = b"000000"
    response = client.post(
        "/tf-validate", data=dict(code=wrong_code), follow_redirects=True
    )

    message = b"You currently do not have permissions to access this page"
    assert message in response.data

    # Test login using invalid email
    data = dict(email="nobody@lp.com", password="password")
    response = client.post("/login", data=data, follow_redirects=True)
    assert b"Specified user does not exist" in response.data
    response = client.post(
        "/login",
        json=data,
        headers={"Content-Type": "application/json"},
        follow_redirects=True,
    )
    assert b"Specified user does not exist" in response.data

    # Test login using valid email and invalid password
    data = dict(email="gal@lp.com", password="wrong_pass")
    response = client.post("/login", data=data, follow_redirects=True)
    assert b"Invalid password" in response.data
    response = client.post(
        "/login",
        json=data,
        headers={"Content-Type": "application/json"},
        follow_redirects=True,
    )
    assert b"Invalid password" in response.data

    # Test two-factor authentication first login
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login", data=data, follow_redirects=True)
    message = b"Two-factor authentication adds an extra layer of security"
    assert message in response.data
    response = client.post(
        "/tf-setup", data=dict(setup="not_a_method"), follow_redirects=True
    )
    assert b"Marked method is not valid" in response.data
    session = get_session(response)
    assert session["tf_state"] == "setup_from_login"

    # try non-existing setup on setup page (using json)
    data = dict(setup="not_a_method")
    response = client.post(
        "/tf-setup",
        json=data,
        headers={"Content-Type": "application/json"},
        follow_redirects=True,
    )
    assert response.status_code == 400
    assert (
        response.json["response"]["errors"]["setup"][0] == "Marked method is not valid"
    )

    data = dict(setup="email")
    response = client.post(
        "/tf-setup",
        json=data,
        headers={"Content-Type": "application/json"},
        follow_redirects=True,
    )

    # Test for sms in process of valid login
    sms_sender = SmsSenderFactory.createSender("test")
    data = dict(email="gal@lp.com", password="password")
    response = client.post(
        "/login",
        json=data,
        headers={"Content-Type": "application/json"},
        follow_redirects=True,
    )
    assert b'"code": 200' in response.data
    assert sms_sender.get_count() == 1
    session = get_session(response)
    assert session["tf_state"] == "ready"

    code = sms_sender.messages[0].split()[-1]
    # submit bad token to two_factor_token_validation
    response = client.post("/tf-validate", data=dict(code=wrong_code))
    assert b"Invalid Token" in response.data

    # sumbit right token and show appropriate response
    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert b"Your token has been confirmed" in response.data

    # Upon completion, session cookie shouldnt have any two factor stuff in it.
    assert not tf_in_session(get_session(response))

    # try confirming password with a wrong one
    response = client.post("/tf-confirm", data=dict(password=""), follow_redirects=True)
    assert b"Password not provided" in response.data

    # try confirming password with a wrong one + json
    data = dict(password="wrong_password")
    response = client.post(
        "/tf-confirm",
        json=data,
        headers={"Content-Type": "application/json"},
        follow_redirects=True,
    )

    assert response.json["meta"]["code"] == 400

    # Test change two_factor password confirmation view to mail
    password = "password"
    response = client.post(
        "/tf-confirm", data=dict(password=password), follow_redirects=True
    )

    assert b"You successfully confirmed password" in response.data
    message = b"Two-factor authentication adds an extra layer of security"
    assert message in response.data

    # change method (from sms to mail)
    setup_data = dict(setup="email")
    testMail = TestMail()
    app.extensions["mail"] = testMail
    response = client.post("/tf-setup", data=setup_data, follow_redirects=True)
    msg = b"To complete logging in, please enter the code sent to your mail"
    assert msg in response.data

    # Fetch token validate form
    response = client.get("/tf-validate")
    assert response.status_code == 200
    assert b'name="code"' in response.data

    code = testMail.msg.body.split()[-1]
    # sumbit right token and show appropriate response
    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert b"You successfully changed your two-factor method" in response.data

    # Test change two_factor password confirmation view to google authenticator
    password = "password"
    response = client.post(
        "/tf-confirm", data=dict(password=password), follow_redirects=True
    )
    assert b"You successfully confirmed password" in response.data
    message = b"Two-factor authentication adds an extra layer of security"
    assert message in response.data

    # Setup authenticator
    setup_data = dict(setup="authenticator")
    response = client.post("/tf-setup", data=setup_data, follow_redirects=True)
    assert b"Open your authenticator app on your device" in response.data

    # Now request code. We can't test the qrcode easily - but we can get the totp_secret
    # that goes into the qrcode and make sure that works
    mtf = Mock(wraps=app.security._totp_factory)
    app.security.totp_factory(mtf)
    qrcode_page_response = client.get(
        "/tf-qrcode", data=setup_data, follow_redirects=True
    )
    assert mtf.get_totp_uri.call_count == 1
    (username, totp_secret), _ = mtf.get_totp_uri.call_args
    assert username == "gal@lp.com"
    assert b"svg" in qrcode_page_response.data

    # Generate token from passed totp_secret and confirm setup
    code = app.security._totp_factory.generate_totp_password(totp_secret)
    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert b"You successfully changed your two-factor method" in response.data

    logout(client)

    # Test login with remember_token
    assert "remember_token" not in [c.name for c in client.cookie_jar]
    data = dict(email="gal@lp.com", password="password", remember=True)
    response = client.post(
        "/login",
        json=data,
        headers={"Content-Type": "application/json"},
        follow_redirects=True,
    )

    # Generate token from passed totp_secret
    code = app.security._totp_factory.generate_totp_password(totp_secret)
    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert b"Your token has been confirmed" in response.data

    # Verify that the remember token is properly set
    found = False
    for cookie in client.cookie_jar:
        if cookie.name == "remember_token":
            found = True
            assert cookie.path == "/"
    assert found

    response = logout(client)
    # Verify that logout clears session info
    assert not tf_in_session(get_session(response))

    # Test two-factor authentication first login
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login", data=data, follow_redirects=True)
    message = b"Two-factor authentication adds an extra layer of security"
    assert message in response.data

    # check availability of qrcode page when this option is not picked
    qrcode_page_response = client.get("/two_factor_qrcode/", follow_redirects=False)
    assert qrcode_page_response.status_code == 404

    # check availability of qrcode page when this option is picked
    setup_data = dict(setup="authenticator")
    response = client.post("/tf-setup", data=setup_data, follow_redirects=True)
    assert b"Open your authenticator app on your device" in response.data

    qrcode_page_response = client.get(
        "/tf-qrcode", data=setup_data, follow_redirects=True
    )
    print(qrcode_page_response)
    assert b"svg" in qrcode_page_response.data

    # check appearence of setup page when sms picked and phone number entered
    sms_sender = SmsSenderFactory.createSender("test")
    data = dict(setup="sms", phone="+442083661177")
    response = client.post("/tf-setup", data=data, follow_redirects=True)
    assert b"To Which Phone Number Should We Send Code To" in response.data
    assert sms_sender.get_count() == 1
    code = sms_sender.messages[0].split()[-1]

    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert b"Your token has been confirmed" in response.data
    assert not tf_in_session(get_session(response))

    logout(client)

    # check when two_factor_rescue function should not appear
    rescue_data_json = dict(help_setup="lost_device")
    response = client.post(
        "/tf-rescue",
        json=rescue_data_json,
        headers={"Content-Type": "application/json"},
    )
    assert b'"code": 400' in response.data

    # check when two_factor_rescue function should appear
    data = dict(email="gal2@lp.com", password="password")
    response = client.post("/login", data=data, follow_redirects=True)
    assert b"Please enter your authentication code" in response.data
    rescue_data = dict(help_setup="lost_device")
    response = client.post("/tf-rescue", data=rescue_data, follow_redirects=True)
    message = b"The code for authentication was sent to your email address"
    assert message in response.data
    rescue_data = dict(help_setup="no_mail_access")
    response = client.post("/tf-rescue", data=rescue_data, follow_redirects=True)
    message = b"A mail was sent to us in order to reset your application account"
    assert message in response.data


@pytest.mark.settings(two_factor_required=True)
def test_setup_bad_phone(app, client):
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login", data=data, follow_redirects=True)
    message = b"Two-factor authentication adds an extra layer of security"
    assert message in response.data

    sms_sender = SmsSenderFactory.createSender("test")
    data = dict(setup="sms", phone="555-1212")
    response = client.post("/tf-setup", data=data, follow_redirects=True)
    assert b"Phone number not valid" in response.data
    assert sms_sender.get_count() == 0

    client.post(
        "/tf-setup", data=dict(setup="sms", phone="650-555-1212"), follow_redirects=True
    )
    assert sms_sender.get_count() == 1
    code = sms_sender.messages[0].split()[-1]

    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert b"Your token has been confirmed" in response.data
    assert not tf_in_session(get_session(response))


@pytest.mark.settings(two_factor_required=True)
def test_json(app, client):
    """
    Test all endpoints using JSON. (eventually)
    """

    # Test that user not yet setup for 2FA gets correct response.
    data = dict(email="matt@lp.com", password="password")
    response = client.post(
        "/login", json=data, headers={"Content-Type": "application/json"}
    )
    assert response.json["response"]["tf_required"]
    assert response.json["response"]["tf_state"] == "setup_from_login"

    # Login with someone already setup.
    sms_sender = SmsSenderFactory.createSender("test")
    data = dict(email="gal@lp.com", password="password")
    response = client.post(
        "/login", json=data, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 200
    assert response.json["response"]["tf_required"]
    assert response.json["response"]["tf_state"] == "ready"
    assert response.json["response"]["tf_primary_method"] == "sms"

    # Verify SMS sent
    assert sms_sender.get_count() == 1

    code = sms_sender.messages[0].split()[-1]
    response = client.post(
        "/tf-validate",
        json=dict(code=code),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200


@pytest.mark.settings(two_factor_required=True)
def test_no_opt_out(app, client):
    # Test if 2FA required, can't opt-out.
    sms_sender = SmsSenderFactory.createSender("test")
    response = client.post(
        "/login",
        data=dict(email="gal@lp.com", password="password"),
        follow_redirects=True,
    )
    assert sms_sender.get_count() == 1
    code = sms_sender.messages[0].split()[-1]

    # submit right token and show appropriate response
    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert b"Your token has been confirmed" in response.data

    response = client.post(
        "/tf-confirm", data=dict(password="password"), follow_redirects=True
    )
    assert b"You successfully confirmed password" in response.data

    response = client.get("/tf-setup", follow_redirects=True)
    assert b"Disable two factor" not in response.data

    # Try to opt-out
    data = dict(setup="disable")
    response = client.post("/tf-setup", data=data, follow_redirects=True)
    assert response.status_code == 200
    assert b"Marked method is not valid" in response.data


@pytest.mark.settings(
    two_factor_setup_url="/custom-setup", two_factor_rescue_url="/custom-rescue"
)
def test_custom_urls(client):
    response = client.get("/tf-setup")
    assert response.status_code == 404
    response = client.get("/custom-setup")
    assert response.status_code == 302
    response = client.get("/custom-rescue")
    assert response.status_code == 302


def test_evil_validate(app, client):
    """
    Test logged in, and randomly try to validate a token
    """
    signalled_identity = []

    @identity_changed.connect_via(app)
    def on_identity_changed(app, identity):
        signalled_identity.append(identity.id)

    response = authenticate(client, "jill@lp.com")
    session = get_session(response)
    assert "tf_state" not in session
    # Jill is 4th user to be added in test_utils.py
    assert signalled_identity[0] == 4
    del signalled_identity[:]

    # try to validate
    response = client.post("/tf-validate", data=dict(code="?"), follow_redirects=True)
    # This should log us out since it thinks we are evil
    assert not signalled_identity[0]
    del signalled_identity[:]


def test_opt_in(app, client):
    """
    Test entire lifecycle of user not having 2FA - setting it up, then deciding
    to turn it back off
    All using forms based API
    """

    signalled_identity = []

    @identity_changed.connect_via(app)
    def on_identity_changed(app, identity):
        signalled_identity.append(identity.id)

    response = authenticate(client, "jill@lp.com")
    session = get_session(response)
    assert "tf_state" not in session
    # Jill is 4th user to be added in test_utils.py
    assert signalled_identity[0] == 4
    del signalled_identity[:]

    # opt-in for SMS 2FA - but we haven't re-verified password
    sms_sender = SmsSenderFactory.createSender("test")
    data = dict(setup="sms", phone="+442083661177")
    response = client.post("/tf-setup", data=data, follow_redirects=True)
    message = b"You currently do not have permissions to access this page"
    assert message in response.data

    # Confirm password - then opt-in
    password = "password"
    response = client.post(
        "/tf-confirm", data=dict(password=password), follow_redirects=True
    )
    data = dict(setup="sms", phone="+442083661177")
    response = client.post("/tf-setup", data=data, follow_redirects=True)
    assert b"To Which Phone Number Should We Send Code To" in response.data
    assert sms_sender.get_count() == 1
    code = sms_sender.messages[0].split()[-1]

    # Validate token - this should complete 2FA setup
    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert b"You successfully changed" in response.data

    # Upon completion, session cookie shouldnt have any two factor stuff in it.
    session = get_session(response)
    assert not tf_in_session(session)

    # Log out
    logout(client)
    assert not signalled_identity[0]
    del signalled_identity[:]

    # Login now should require 2FA with sms
    sms_sender = SmsSenderFactory.createSender("test")
    response = authenticate(client, "jill@lp.com")
    session = get_session(response)
    assert session["tf_state"] == "ready"
    assert len(signalled_identity) == 0

    assert sms_sender.get_count() == 1
    code = sms_sender.messages[0].split()[-1]
    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert b"Your token has been confirmed" in response.data
    # Verify now logged in
    assert signalled_identity[0] == 4
    del signalled_identity[:]

    # Now opt back out.
    # as before must reconfirm password first
    response = client.get("/tf-setup", data=data, follow_redirects=True)
    message = b"You currently do not have permissions to access this page"
    assert message in response.data

    password = "password"
    client.post("/tf-confirm", data=dict(password=password), follow_redirects=True)
    data = dict(setup="disable")
    response = client.post("/tf-setup", data=data, follow_redirects=True)
    assert b"You successfully disabled two factor authorization." in response.data

    # Log out
    logout(client)
    assert not signalled_identity[0]
    del signalled_identity[:]

    # Should be able to log in with just user/pass
    response = authenticate(client, "jill@lp.com")
    session = get_session(response)
    assert "tf_state" not in session
    # Jill is 4th user to be added in test_utils.py
    assert signalled_identity[0] == 4


@pytest.mark.recoverable()
@pytest.mark.settings(two_factor_required=True)
def test_recoverable(app, client, get_message):
    # make sure 'forgot password' doesn't bypass 2FA.
    # 'gal@lp.com' already setup for SMS

    rtokens = []
    sms_sender = SmsSenderFactory.createSender("test")

    @reset_password_instructions_sent.connect_via(app)
    def on_instructions_sent(sapp, **kwargs):
        rtokens.append(kwargs["token"])

    client.post("/reset", data=dict(email="gal@lp.com"), follow_redirects=True)
    response = client.post(
        "/reset/" + rtokens[0],
        data={"password": "awesome sunset", "password_confirm": "awesome sunset"},
        follow_redirects=True,
    )
    # Should have redirected us to the 2FA login page
    assert b"Please enter your authentication code" in response.data

    # we shouldn't be logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 302

    # Grab code that was sent
    assert sms_sender.get_count() == 1
    code = sms_sender.messages[0].split()[-1]
    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert b"Your token has been confirmed" in response.data

    # verify we are logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200


@pytest.mark.settings(two_factor_required=True)
def test_admin_setup_reset(app, client, get_message):
    # Verify can use administrative datastore method to setup SMS
    # and that administrative reset removes access.
    sms_sender = SmsSenderFactory.createSender("test")

    data = dict(email="gene@lp.com", password="password")
    response = client.post(
        "/login", json=data, headers={"Content-Type": "application/json"}
    )
    assert response.json["response"]["tf_required"]

    # we shouldn't be logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 302
    assert response.location == "http://localhost/login?next=%2Fprofile"

    # Use admin to setup gene's SMS/phone.
    with app.app_context():
        user = app.security.datastore.find_user(email="gene@lp.com")
        totp_secret = app.security._totp_factory.generate_totp_secret()
        app.security.datastore.tf_set(user, "sms", totp_secret, phone="+442083661177")
        app.security.datastore.commit()

    response = authenticate(client, "gene@lp.com")
    session = get_session(response)
    assert session["tf_state"] == "ready"

    # Grab code that was sent
    assert sms_sender.get_count() == 1
    code = sms_sender.messages[0].split()[-1]
    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert b"Your token has been confirmed" in response.data

    # verify we are logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 200

    # logout
    logout(client)

    # use administrative reset method
    with app.app_context():
        user = app.security.datastore.find_user(email="gene@lp.com")
        app.security.datastore.reset_user_access(user)
        app.security.datastore.commit()

    data = dict(email="gene@lp.com", password="password")
    response = client.post(
        "/login", json=data, headers={"Content-Type": "application/json"}
    )
    assert response.json["response"]["tf_required"]
    assert response.json["response"]["tf_state"] == "setup_from_login"

    # we shouldn't be logged in
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 302


@pytest.mark.settings(two_factor_required=True)
def test_datastore(app, client):
    # Test that user record is properly set after proper 2FA setup.
    sms_sender = SmsSenderFactory.createSender("test")
    data = dict(email="gene@lp.com", password="password")
    response = client.post(
        "/login", json=data, headers={"Content-Type": "application/json"}
    )
    assert response.json["meta"]["code"] == 200
    session = get_session(response)
    assert session["tf_state"] == "setup_from_login"

    # setup
    data = dict(setup="sms", phone="+442083661177")
    response = client.post(
        "/tf-setup", json=data, headers={"Content-Type": "application/json"}
    )

    assert sms_sender.get_count() == 1
    session = get_session(response)
    assert session["tf_state"] == "validating_profile"
    assert session["tf_primary_method"] == "sms"

    code = sms_sender.messages[0].split()[-1]

    # submit token and show appropriate response
    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert b"Your token has been confirmed" in response.data
    session = get_session(response)
    # Verify that successful login clears session info
    assert not tf_in_session(session)

    with app.app_context():
        user = app.security.datastore.find_user(email="gene@lp.com")
        assert user.tf_primary_method == "sms"
        assert user.tf_phone_number == "+442083661177"
        assert "enckey" in user.tf_totp_secret


def test_totp_secret_generation(app, client):
    """
    Test the totp secret generation upon changing method to make sure
    it stays the same after the process is completed
    """

    # Properly log in jill for this test
    signalled_identity = []

    @identity_changed.connect_via(app)
    def on_identity_changed(app, identity):
        signalled_identity.append(identity.id)

    response = authenticate(client, "jill@lp.com")
    session = get_session(response)
    assert "tf_state" not in session
    # Jill is 4th user to be added in test_utils.py
    assert signalled_identity[0] == 4
    del signalled_identity[:]

    # Confirm password
    sms_sender = SmsSenderFactory.createSender("test")
    password = "password"
    response = client.post(
        "/tf-confirm", data=dict(password=password), follow_redirects=True
    )
    # Select sms method but do not send a phone number just yet (regenerates secret)
    data = dict(setup="sms")
    response = client.post("/tf-setup", data=data, follow_redirects=True)
    assert b"To Which Phone Number Should We Send Code To" in response.data

    # Retrieve the currently generated totp secret for later comparison
    session = get_session(response)
    if "tf_totp_secret" in session:
        generated_secret = session["tf_totp_secret"]
    else:
        with app.app_context():
            user = app.security.datastore.find_user(email="jill@lp.com")
            generated_secret = user.tf_totp_secret
    assert "enckey" in generated_secret

    # Send a new phone number in the second step, method remains unchanged
    data = dict(setup="sms", phone="+442083661188")
    response = client.post("/tf-setup", data=data, follow_redirects=True)
    assert sms_sender.get_count() == 1
    code = sms_sender.messages[0].split()[-1]

    # Validate token - this should complete 2FA setup
    response = client.post("/tf-validate", data=dict(code=code), follow_redirects=True)
    assert b"You successfully changed" in response.data

    # Retrieve the final totp secret and make sure it matches the previous one
    with app.app_context():
        user = app.security.datastore.find_user(email="jill@lp.com")
        assert generated_secret == user.tf_totp_secret

    # Finally opt back out and check that tf_totp_secret is None
    response = client.get("/tf-setup", data=data, follow_redirects=True)
    message = b"You currently do not have permissions to access this page"
    assert message in response.data

    password = "password"
    client.post("/tf-confirm", data=dict(password=password), follow_redirects=True)
    data = dict(setup="disable")
    response = client.post("/tf-setup", data=data, follow_redirects=True)
    assert b"You successfully disabled two factor authorization." in response.data
    with app.app_context():
        user = app.security.datastore.find_user(email="jill@lp.com")
        assert user.tf_totp_secret is None

    # Log out
    logout(client)
    assert not signalled_identity[0]
    del signalled_identity[:]


@pytest.mark.settings(two_factor_enabled_methods=["authenticator"])
def test_just_authenticator(app, client):
    authenticate(client, email="jill@lp.com")
    password = "password"
    client.post("/tf-confirm", data=dict(password=password), follow_redirects=True)

    response = client.get("/tf-setup", follow_redirects=True)
    assert b"Set up using SMS" not in response.data

    data = dict(setup="authenticator")
    response = client.post("/tf-setup", data=data, follow_redirects=True)
    assert b"Submit Code" in response.data

    # test json
    response = client.post("/tf-setup", json=data)
    assert response.status_code == 200


@pytest.mark.settings(USER_IDENTITY_ATTRIBUTES=("username", "email"))
def test_qrcode_identity(app, client):
    # Setup authenticator
    authenticate(client, email="jill@lp.com")

    client.post("/tf-confirm", data=dict(password="password"), follow_redirects=True)
    setup_data = dict(setup="authenticator")
    response = client.post("/tf-setup", data=setup_data, follow_redirects=True)
    assert b"Open your authenticator app on your device" in response.data

    # Now request code. Verify that we get 'username' not email.
    mtf = Mock(wraps=app.security._totp_factory)
    app.security.totp_factory(mtf)
    qrcode_page_response = client.get(
        "/tf-qrcode", data=setup_data, follow_redirects=True
    )
    assert mtf.get_totp_uri.call_count == 1
    (username, totp_secret), _ = mtf.get_totp_uri.call_args
    assert username == "jill"
    assert b"svg" in qrcode_page_response.data


@pytest.mark.settings(USER_IDENTITY_ATTRIBUTES=("security_number", "email"))
def test_qrcode_identity_num(app, client):
    # Setup authenticator
    authenticate(client, email="jill@lp.com")

    client.post("/tf-confirm", data=dict(password="password"), follow_redirects=True)
    setup_data = dict(setup="authenticator")
    response = client.post("/tf-setup", data=setup_data, follow_redirects=True)
    assert b"Open your authenticator app on your device" in response.data

    # Now request code. Verify that we get 'security_number' not email.
    mtf = Mock(wraps=app.security._totp_factory)
    app.security.totp_factory(mtf)
    qrcode_page_response = client.get(
        "/tf-qrcode", data=setup_data, follow_redirects=True
    )
    assert mtf.get_totp_uri.call_count == 1
    (username, totp_secret), _ = mtf.get_totp_uri.call_args
    assert username == "456789"
    assert b"svg" in qrcode_page_response.data


@pytest.mark.settings(USER_IDENTITY_ATTRIBUTES=("email", "username"))
def test_email_salutation(app, client):

    authenticate(client, email="jill@lp.com")
    client.post("/tf-confirm", data=dict(password="password"), follow_redirects=True)

    test_mail = TestMail()
    app.extensions["mail"] = test_mail
    response = client.post("/tf-setup", data=dict(setup="email"), follow_redirects=True)
    msg = b"To complete logging in, please enter the code sent to your mail"
    assert msg in response.data

    assert "jill@lp.com" in test_mail.msg.send_to
    assert "jill@lp.com" in test_mail.msg.body
    assert "jill@lp.com" in test_mail.msg.html


@pytest.mark.settings(USER_IDENTITY_ATTRIBUTES=("username", "email"))
def test_username_salutation(app, client):

    authenticate(client, email="jill@lp.com")
    client.post("/tf-confirm", data=dict(password="password"), follow_redirects=True)

    test_mail = TestMail()
    app.extensions["mail"] = test_mail
    response = client.post("/tf-setup", data=dict(setup="email"), follow_redirects=True)
    msg = b"To complete logging in, please enter the code sent to your mail"
    assert msg in response.data

    assert "jill@lp.com" in test_mail.msg.send_to
    assert "jill@lp.com" not in test_mail.msg.body
    assert "jill@lp.com" not in test_mail.msg.html
    assert "jill" in test_mail.msg.body


@pytest.mark.settings(sms_service="bad")
def test_bad_sender(app, client, get_message):
    # If SMS sender fails - make sure propagated
    # Test form, json, x signin, setup
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    # test normal, already setup up login.
    with capture_flashes() as flashes:
        data = {"email": "gal@lp.com", "password": "password"}
        response = client.post("login", data=data, follow_redirects=False)
        assert response.status_code == 302
        assert response.location == "http://localhost/login"
    assert get_message("FAILED_TO_SEND_CODE") in flashes[0]["message"].encode("utf-8")

    # test w/ JSON
    data = dict(email="gal@lp.com", password="password")
    response = client.post("login", json=data, headers=headers)
    assert response.status_code == 500
    assert response.json["response"]["error"].encode("utf-8") == get_message(
        "FAILED_TO_SEND_CODE"
    )

    # Now test setup
    tf_authenticate(app, client)
    client.post("/tf-confirm", data=dict(password="password"), follow_redirects=True)
    data = dict(setup="sms", phone="+442083661188")
    response = client.post("tf-setup", data=data)
    assert get_message("FAILED_TO_SEND_CODE") in response.data

    response = client.post("tf-setup", json=data, headers=headers)
    assert response.status_code == 500
    assert response.json["response"]["errors"]["setup"][0].encode(
        "utf-8"
    ) == get_message("FAILED_TO_SEND_CODE")


@pytest.mark.registerable()
def test_replace_send_code(app, get_message):
    # replace tf_send_code - and have it return an error to check that.
    from flask_sqlalchemy import SQLAlchemy
    from flask_security.models import fsqla_v2 as fsqla
    from flask_security import Security, hash_password

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    db = SQLAlchemy(app)

    fsqla.FsModels.set_db_info(db)

    class Role(db.Model, fsqla.FsRoleMixin):
        pass

    class User(db.Model, fsqla.FsUserMixin):
        rv = [None, "That didnt work out as we planned", "Failed Again"]

        def tf_send_security_token(self, method, **kwargs):
            return User.rv.pop(0)

    with app.app_context():
        db.create_all()

    ds = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(app, datastore=ds)

    with app.app_context():
        client = app.test_client()

        ds.create_user(
            email="trp@lp.com",
            password=hash_password("password"),
            tf_primary_method="sms",
            tf_totp_secret=app.security._totp_factory.generate_totp_secret(),
        )
        ds.commit()

        data = dict(email="trp@lp.com", password="password")
        response = client.post("/login", data=data, follow_redirects=True)
        assert b"Please enter your authentication code" in response.data
        rescue_data = dict(help_setup="lost_device")
        response = client.post("/tf-rescue", data=rescue_data, follow_redirects=True)
        assert b"That didnt work out as we planned" in response.data

        # Test JSON
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        response = client.post("/tf-rescue", json=rescue_data, headers=headers)
        assert response.status_code == 500
        assert response.json["response"]["errors"]["help_setup"][0] == "Failed Again"
