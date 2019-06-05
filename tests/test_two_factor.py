# -*- coding: utf-8 -*-
"""
    test_two_factor
    ~~~~~~~~~~~~~~~~~

    two_factor tests

    :copyright: (c) 2019
    :license: MIT, see LICENSE for more details.
"""

from flask import json
import pytest

from utils import get_session, logout
from flask_security.utils import SmsSenderBaseClass, SmsSenderFactory

pytestmark = pytest.mark.two_factor()


class SmsTestSender(SmsSenderBaseClass):
    SmsSenderBaseClass.messages = []
    SmsSenderBaseClass.count = 0

    def __init__(self):
        super(SmsTestSender, self).__init__()
        SmsSenderBaseClass.count = 0
        SmsSenderBaseClass.messages = []

    def send_sms(self, from_number, to_number, msg):
        SmsSenderBaseClass.messages.append(msg)
        SmsSenderBaseClass.count += 1
        return

    def get_count(self):
        return SmsSenderBaseClass.count


SmsSenderFactory.senders['test'] = SmsTestSender


class TestMail():

    # def __init__(self):
    #     self.count = 0
    #     self.msg = ""

    def send(self, msg):
        if not self.msg:
            self.msg = ""
        if not self.count:
            self.count = 0
        self.msg = msg
        self.count += 1


def assert_flashes(client, expected_message, expected_category='message'):
    with client.session_transaction() as session:
        try:
            category, message = session['_flashes'][0]
        except KeyError:
            raise AssertionError('nothing flashed')
        assert expected_message in message
        assert expected_category == category


def two_factor_authenticate(client, validate=True):
    """ Login/Authenticate using two factor.
    This is the equivalent of utils:authenticate
    """
    sms_sender = SmsSenderFactory.createSender('test')
    json_data = '{"email": "gal@lp.com", "password": "password"}'
    response = client.post('/login', data=json_data,
                           headers={'Content-Type': 'application/json'})
    assert b'"code": 200' in response.data

    if validate:
        code = sms_sender.messages[0].split()[-1]
        response = client.post('/tf-validate',
                               data=dict(code=code),
                               follow_redirects=True)
        assert response.status_code == 200


def test_two_factor_two_factor_setup_function_anonymous(app, client):

    # trying to pick method without doing earlier stage
    data = dict(setup="mail")
    response = client.post('/tf-setup', data=data)
    assert response.status_code == 302
    flash_message = 'You currently do not have permissions to access this page'
    assert_flashes(client, flash_message, expected_category='error')


def test_two_factor_flag(app, client):
    # trying to verify code without going through two-factor
    # first login function
    wrong_code = b'000000'
    response = client.post('/tf-validate',
                           data=dict(code=wrong_code),
                           follow_redirects=True)

    message = b'You currently do not have permissions to access this page'
    assert message in response.data

    # Test login using invalid email
    data = dict(email="nobody@lp.com", password="password")
    response = client.post('/login', data=data, follow_redirects=True)
    assert b'Specified user does not exist' in response.data
    json_data = '{"email": "nobody@lp.com", "password": "password"}'
    response = client.post('/login',
                           data=json_data,
                           headers={'Content-Type': 'application/json'},
                           follow_redirects=True)
    assert b'Specified user does not exist' in response.data

    # Test login using valid email and invalid password
    data = dict(email="gal@lp.com", password="wrong_pass")
    response = client.post('/login', data=data, follow_redirects=True)
    assert b'Invalid password' in response.data
    json_data = '{"email": "gal@lp.com", "password": "wrong_pass"}'
    response = client.post('/login', data=json_data,
                           headers={'Content-Type': 'application/json'},
                           follow_redirects=True)
    assert b'Invalid password' in response.data

    # Test two-factor authentication first login
    data = dict(email="matt@lp.com", password="password")
    response = client.post('/login', data=data, follow_redirects=True)
    message = b'Two-factor authentication adds an extra layer of security'
    assert message in response.data
    response = client.post('/tf-setup',
                           data=dict(setup="not_a_method"),
                           follow_redirects=True)
    assert b'Marked method is not valid' in response.data
    session = get_session(response)
    assert not session['has_two_factor']

    # try non-existing setup on setup page (using json)
    json_data = '{"setup": "not_a_method"}'
    response = client.post('/tf-setup',
                           data=json_data,
                           headers={'Content-Type': 'application/json'},
                           follow_redirects=True)
    assert b'"response": {}' in response.data

    json_data = '{"setup": "mail"}'
    response = client.post('/tf-setup',
                           data=json_data,
                           headers={'Content-Type': 'application/json'},
                           follow_redirects=True)

    # Test for sms in process of valid login
    sms_sender = SmsSenderFactory.createSender('test')
    json_data = '{"email": "gal@lp.com", "password": "password"}'
    response = client.post('/login', data=json_data,
                           headers={'Content-Type': 'application/json'},
                           follow_redirects=True)
    assert b'"code": 200' in response.data
    assert sms_sender.get_count() == 1
    session = get_session(response)
    assert session['email'] == 'gal@lp.com'
    assert session['has_two_factor']
    assert session['primary_method'] == 'sms'
    # Make sure totp_secret it properly encrypted
    totp_secret = json.loads(session['totp_secret'])
    assert 'enckey' in totp_secret

    code = sms_sender.messages[0].split()[-1]

    # submit bad token to two_factor_token_validation
    response = client.post('/tf-validate',
                           data=dict(code=wrong_code))
    assert b'Invalid Token' in response.data

    # sumbit right token and show appropriate response
    response = client.post('/tf-validate',
                           data=dict(code=code),
                           follow_redirects=True)
    assert b'Your token has been confirmed' in response.data

    # Upon completion, session cookie shouldnt have any two factor stuff in it.
    session = get_session(response)
    assert not any(k in session for k in ['email', 'has_two_factor', 'totp_secret',
                                          'password_confirmed'])

    # try confirming password with a wrong one
    response = client.post('/tf-confirm',
                           data=dict(password=""),
                           follow_redirects=True)
    assert b'Invalid password' in response.data

    # try confirming password with a wrong one + json
    json_data = '{"password": "wrong_password"}'
    response = client.post('/tf-confirm',
                           data=json_data, headers={
                               'Content-Type': 'application/json'},
                           follow_redirects=True)

    assert response.jdata['meta']['code'] == 400

    # Test change two_factor password confirmation view to mail
    password = 'password'
    response = client.post('/tf-confirm',
                           data=dict(password=password), follow_redirects=True)

    assert b'You successfully confirmed password' in response.data
    message = b'Two-factor authentication adds an extra layer of security'
    assert message in response.data

    # change method (from sms to mail)
    setup_data = dict(setup='mail')
    testMail = TestMail()
    testMail.msg = ""
    testMail.count = 0
    app.extensions['mail'] = testMail
    response = client.post('/tf-setup',
                           data=setup_data, follow_redirects=True)
    msg = b'To complete logging in, please enter the code sent to your mail'
    assert msg in response.data

    code = testMail.msg.body.split()[-1]
    # sumbit right token and show appropriate response
    response = client.post('/tf-validate',
                           data=dict(code=code),
                           follow_redirects=True)
    assert b'You successfully changed your two-factor method' in response.data

    # Test change two_factor password confirmation view to google authenticator
    password = 'password'
    response = client.post('/tf-confirm',
                           data=dict(password=password), follow_redirects=True)
    assert b'You successfully confirmed password' in response.data
    message = b'Two-factor authentication adds an extra layer of security'
    assert message in response.data
    setup_data = dict(setup='google_authenticator')
    response = client.post('/tf-setup',
                           data=setup_data, follow_redirects=True)

    assert b'Open Google Authenticator on your device' in response.data
    qrcode_page_response = client.get('/tf-qrcode', data=setup_data,
                                      follow_redirects=True)
    print(qrcode_page_response)
    assert b'svg' in qrcode_page_response.data

    logout(client)

    # Test for google_authenticator (test)
    json_data = '{"email": "gal2@lp.com", "password": "password"}'
    response = client.post('/login', data=json_data,
                           headers={'Content-Type': 'application/json'},
                           follow_redirects=True)
    session = get_session(response)

    # This shows how dangerous it is to have even an encrypted totp_secret
    # in the cookie.
    totp_secret = session['totp_secret']
    code = app.security._totp_factory.from_source(totp_secret).generate().token
    response = client.post('/tf-validate',
                           data=dict(code=code),
                           follow_redirects=True)
    assert b'Your token has been confirmed' in response.data

    response = logout(client)
    session = get_session(response)
    # Verify that logout clears session info
    assert not any(k in session for k in ['has_two_factor', 'totp_secret',
                                          'password_confirmed'])

    # Test two-factor authentication first login
    data = dict(email="matt@lp.com", password="password")
    response = client.post('/login', data=data, follow_redirects=True)
    message = b'Two-factor authentication adds an extra layer of security'
    assert message in response.data

    # check availability of qrcode page when this option is not picked
    qrcode_page_response = client.get(
        '/two_factor_qrcode/', follow_redirects=False)
    assert qrcode_page_response.status_code == 404

    # check availability of qrcode page when this option is picked
    setup_data = dict(setup='google_authenticator')
    response = client.post('/tf-setup',
                           data=setup_data, follow_redirects=True)
    assert b'Open Google Authenticator on your device' in response.data

    qrcode_page_response = client.get('/tf-qrcode', data=setup_data,
                                      follow_redirects=True)
    print(qrcode_page_response)
    assert b'svg' in qrcode_page_response.data

    # check appearence of setup page when sms picked and phone number entered
    sms_sender = SmsSenderFactory.createSender('test')
    data = dict(setup='sms', phone="+111111111111")
    response = client.post('/tf-setup',
                           data=data, follow_redirects=True)
    assert b'To Which Phone Number Should We Send Code To' in response.data
    assert sms_sender.get_count() == 1
    code = sms_sender.messages[0].split()[-1]

    response = client.post('/tf-validate',
                           data=dict(code=code),
                           follow_redirects=True)
    assert b'Your token has been confirmed' in response.data

    logout(client)

    # check when two_factor_rescue function should not appear
    rescue_data_json = '{"help_setup": "lost_device"}'
    response = client.post('/tf-rescue',
                           data=rescue_data_json,
                           headers={'Content-Type': 'application/json'})
    assert b'"code": 400' in response.data

    # check when two_factor_rescue function should appear
    data = dict(email="gal2@lp.com", password="password")
    response = client.post('/login', data=data, follow_redirects=True)
    assert b'Please enter your authentication code' in response.data
    rescue_data = dict(help_setup='lost_device')
    response = client.post('/tf-rescue',
                           data=rescue_data, follow_redirects=True)
    message = b'The code for authentication was sent to your email address'
    assert message in response.data
    rescue_data = dict(help_setup='no_mail_access')
    response = client.post('/tf-rescue',
                           data=rescue_data, follow_redirects=True)
    message = (b'A mail was sent to us in order' +
               b' to reset your application account')
    assert message in response.data


def test_json(app, client):
    """
    Test all endpoints using JSON. (eventually)
    """

    # Test that user not yet setup for 2FA gets correct response.
    json_data = '{"email": "matt@lp.com", "password": "password"}'
    response = client.post('/login', data=json_data,
                           headers={'Content-Type': 'application/json'})
    assert response.jdata['response']['two_factor_required']
    assert not response.jdata['response']['two_factor_setup_complete']

    # Login with someone already setup.
    sms_sender = SmsSenderFactory.createSender('test')
    json_data = '{"email": "gal@lp.com", "password": "password"}'
    response = client.post('/login', data=json_data,
                           headers={'Content-Type': 'application/json'})
    assert response.status_code == 200
    assert response.jdata['response']['two_factor_required']
    assert response.jdata['response']['two_factor_setup_complete']
    assert response.jdata['response']['two_factor_primary_method'] == 'sms'

    # Verify SMS sent
    assert sms_sender.get_count() == 1

    code = sms_sender.messages[0].split()[-1]
    response = client.post('/tf-validate',
                           data=json.dumps({'code': code}),
                           headers={'Content-Type': 'application/json'})
    assert response.status_code == 200


@pytest.mark.settings(two_factor_setup_url='/custom-setup',
                      two_factor_rescue_url='/custom-rescue')
def test_custom_urls(client):
    response = client.get('/tf-setup')
    assert response.status_code == 404
    response = client.get('/custom-setup')
    assert response.status_code == 302
    response = client.get('/custom-rescue')
    assert response.status_code == 302


def test_datastore(app, client):
    # Test that user record is properly set after proper 2FA setup.
    sms_sender = SmsSenderFactory.createSender('test')
    json_data = '{"email": "gal@lp.com", "password": "password"}'
    response = client.post('/login', data=json_data,
                           headers={'Content-Type': 'application/json'})
    assert b'"code": 200' in response.data
    assert sms_sender.get_count() == 1
    session = get_session(response)
    assert session['email'] == 'gal@lp.com'
    assert session['has_two_factor']
    assert session['primary_method'] == 'sms'
    # Make sure totp_secret it properly encrypted
    totp_secret = json.loads(session['totp_secret'])
    assert 'enckey' in totp_secret

    code = sms_sender.messages[0].split()[-1]

    # sumbit right token and show appropriate response
    response = client.post('/tf-validate',
                           data=dict(code=code),
                           follow_redirects=True)
    assert b'Your token has been confirmed' in response.data
    session = get_session(response)
    # Verify that sucessfull login clears session info
    assert not any(k in session for k in ['has_two_factor', 'totp_secret',
                                          'password_confirmed'])

    with app.app_context():
        user = app.security.datastore.find_user(email='gal@lp.com')
        assert user.two_factor_primary_method == 'sms'
        assert 'enckey' in user.totp_secret
