# -*- coding: utf-8 -*-
"""
    test_misc
    ~~~~~~~~~~~

    Lots of tests

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import hashlib
import mock
import sys

import pytest

from utils import authenticate, check_xlation, init_app_with_options, populate_data

from flask_security import Security
from flask_security.forms import (
    ChangePasswordForm,
    ConfirmRegisterForm,
    ForgotPasswordForm,
    LoginForm,
    PasswordField,
    PasswordlessLoginForm,
    RegisterForm,
    Required,
    ResetPasswordForm,
    SendConfirmationForm,
    StringField,
    email_required,
    email_validator,
    valid_user_email,
)
from flask_security import auth_required
from flask_security.utils import (
    capture_reset_password_requests,
    encode_string,
    json_error_response,
    hash_data,
    send_mail,
    string_types,
    verify_hash,
)


@pytest.mark.recoverable()
def test_async_email_task(app, client):
    app.mail_sent = False

    @app.security.send_mail_task
    def send_email(msg):
        app.mail_sent = True

    client.post("/reset", data=dict(email="matt@lp.com"))
    assert app.mail_sent is True


@pytest.mark.recoverable()
def test_alt_send_mail(app, sqlalchemy_datastore):
    """ Verify that can override the send_mail method. """
    app.mail_sent = False

    def send_email(subject, email, template, **kwargs):
        app.mail_sent = True

    init_app_with_options(
        app, sqlalchemy_datastore, **{"security_args": {"send_mail": send_email}}
    )
    client = app.test_client()

    client.post("/reset", data=dict(email="matt@lp.com"))
    assert app.mail_sent is True


@pytest.mark.recoverable()
def test_alt_send_mail_decorator(app, client):
    """ Verify that can override the send_mail method. """
    app.mail_sent = False

    @app.security.send_mail
    def send_email(subject, email, template, **kwargs):
        app.mail_sent = True

    client.post("/reset", data=dict(email="matt@lp.com"))
    assert app.mail_sent is True


def test_register_blueprint_flag(app, sqlalchemy_datastore):
    app.security = Security(app, datastore=Security, register_blueprint=False)
    client = app.test_client()
    response = client.get("/login")
    assert response.status_code == 404


@pytest.mark.registerable()
@pytest.mark.recoverable()
@pytest.mark.changeable()
def test_basic_custom_forms(app, sqlalchemy_datastore):
    class MyLoginForm(LoginForm):
        email = StringField("My Login Email Address Field")

    class MyRegisterForm(RegisterForm):
        email = StringField("My Register Email Address Field")

    class MyForgotPasswordForm(ForgotPasswordForm):
        email = StringField(
            "My Forgot Email Address Field",
            validators=[email_required, email_validator, valid_user_email],
        )

    class MyResetPasswordForm(ResetPasswordForm):
        password = StringField("My Reset Password Field")

    class MyChangePasswordForm(ChangePasswordForm):
        password = PasswordField("My Change Password Field")

    app.security = Security(
        app,
        datastore=sqlalchemy_datastore,
        login_form=MyLoginForm,
        register_form=MyRegisterForm,
        forgot_password_form=MyForgotPasswordForm,
        reset_password_form=MyResetPasswordForm,
        change_password_form=MyChangePasswordForm,
    )

    populate_data(app)
    client = app.test_client()

    response = client.get("/login")
    assert b"My Login Email Address Field" in response.data

    response = client.get("/register")
    assert b"My Register Email Address Field" in response.data

    response = client.get("/reset")
    assert b"My Forgot Email Address Field" in response.data

    with capture_reset_password_requests() as requests:
        response = client.post("/reset", data=dict(email="matt@lp.com"))

    token = requests[0]["token"]
    response = client.get("/reset/" + token)
    assert b"My Reset Password Field" in response.data

    authenticate(client)

    response = client.get("/change")
    assert b"My Change Password Field" in response.data


@pytest.mark.registerable()
@pytest.mark.confirmable()
def test_confirmable_custom_form(app, sqlalchemy_datastore):
    app.config["SECURITY_REGISTERABLE"] = True
    app.config["SECURITY_CONFIRMABLE"] = True

    class MyRegisterForm(ConfirmRegisterForm):
        email = StringField("My Register Email Address Field")

    class MySendConfirmationForm(SendConfirmationForm):
        email = StringField("My Send Confirmation Email Address Field")

    app.security = Security(
        app,
        datastore=sqlalchemy_datastore,
        send_confirmation_form=MySendConfirmationForm,
        confirm_register_form=MyRegisterForm,
    )

    client = app.test_client()

    response = client.get("/register")
    assert b"My Register Email Address Field" in response.data

    response = client.get("/confirm")
    assert b"My Send Confirmation Email Address Field" in response.data


def test_passwordless_custom_form(app, sqlalchemy_datastore):
    app.config["SECURITY_PASSWORDLESS"] = True

    class MyPasswordlessLoginForm(PasswordlessLoginForm):
        email = StringField("My Passwordless Email Address Field")

    app.security = Security(
        app,
        datastore=sqlalchemy_datastore,
        passwordless_login_form=MyPasswordlessLoginForm,
    )

    client = app.test_client()

    response = client.get("/login")
    assert b"My Passwordless Email Address Field" in response.data


def test_addition_identity_attributes(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{"SECURITY_USER_IDENTITY_ATTRIBUTES": ("email", "username")}
    )
    client = app.test_client()
    response = authenticate(client, email="matt", follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data


def test_passwordless_and_two_factor_configuration_mismatch(app, sqlalchemy_datastore):
    with pytest.raises(ValueError):
        init_app_with_options(
            app,
            sqlalchemy_datastore,
            **{"SECURITY_TWO_FACTOR": True, "SECURITY_TWO_FACTOR_ENABLED_METHODS": []}
        )


def test_flash_messages_off(app, sqlalchemy_datastore, get_message):
    init_app_with_options(
        app, sqlalchemy_datastore, **{"SECURITY_FLASH_MESSAGES": False}
    )
    client = app.test_client()
    response = client.get("/profile")
    assert get_message("LOGIN") not in response.data


def test_invalid_hash_scheme(app, sqlalchemy_datastore, get_message):
    with pytest.raises(ValueError):
        init_app_with_options(
            app, sqlalchemy_datastore, **{"SECURITY_PASSWORD_HASH": "bogus"}
        )


def test_change_hash_type(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "plaintext",
            "SECURITY_PASSWORD_SALT": None,
            "SECURITY_PASSWORD_SCHEMES": ["bcrypt", "plaintext"],
        }
    )

    app.config["SECURITY_PASSWORD_HASH"] = "bcrypt"
    app.config["SECURITY_PASSWORD_SALT"] = "salty"

    app.security = Security(
        app, datastore=sqlalchemy_datastore, register_blueprint=False
    )

    client = app.test_client()

    response = client.post(
        "/login", data=dict(email="matt@lp.com", password="password")
    )
    assert response.status_code == 302

    response = client.get("/logout")

    response = client.post(
        "/login", data=dict(email="matt@lp.com", password="password")
    )
    assert response.status_code == 302


@pytest.mark.settings(hashing_schemes=["hex_md5"], deprecated_hashing_schemes=[])
@pytest.mark.parametrize("data", [u"hellö", b"hello"])
def test_legacy_hash(in_app_context, data):
    legacy_hash = hashlib.md5(encode_string(data)).hexdigest()
    new_hash = hash_data(data)
    assert legacy_hash == new_hash


def test_hash_data(in_app_context):
    data = hash_data(b"hello")
    assert isinstance(data, string_types)
    data = hash_data(u"hellö")
    assert isinstance(data, string_types)


def test_verify_hash(in_app_context):
    data = hash_data(u"hellö")
    assert verify_hash(data, u"hellö") is True
    assert verify_hash(data, u"hello") is False

    legacy_data = hashlib.md5(encode_string(u"hellö")).hexdigest()
    assert verify_hash(legacy_data, u"hellö") is True
    assert verify_hash(legacy_data, u"hello") is False


@pytest.mark.settings(
    password_salt=u"öööööööööööööööööööööööööööööööööö", password_hash="bcrypt"
)
def test_password_unicode_password_salt(client):
    response = authenticate(client)
    assert response.status_code == 302
    response = authenticate(client, follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data


def test_set_unauthorized_handler(app, client):
    @app.security.unauthorized_handler
    def unauthorized():
        app.unauthorized_handler_set = True
        return "unauthorized-handler-set", 401

    app.unauthorized_handler_set = False

    authenticate(client, "joe@lp.com")
    response = client.get("/admin", follow_redirects=True)

    assert app.unauthorized_handler_set is True
    assert b"unauthorized-handler-set" in response.data
    assert response.status_code == 401


@pytest.mark.registerable()
def test_custom_forms_via_config(app, sqlalchemy_datastore):
    class MyLoginForm(LoginForm):
        email = StringField("My Login Email Address Field")

    class MyRegisterForm(RegisterForm):
        email = StringField("My Register Email Address Field")

    app.config["SECURITY_LOGIN_FORM"] = MyLoginForm
    app.config["SECURITY_REGISTER_FORM"] = MyRegisterForm

    security = Security(datastore=sqlalchemy_datastore)
    security.init_app(app)

    client = app.test_client()

    response = client.get("/login")
    assert b"My Login Email Address Field" in response.data

    response = client.get("/register")
    assert b"My Register Email Address Field" in response.data


def test_form_required(app, sqlalchemy_datastore):
    class MyLoginForm(LoginForm):
        myfield = StringField("My Custom Field", validators=[Required()])

    app.config["SECURITY_LOGIN_FORM"] = MyLoginForm

    security = Security(datastore=sqlalchemy_datastore)
    security.init_app(app)

    client = app.test_client()

    response = client.post("/login", content_type="application/json")
    assert response.status_code == 400
    assert b"myfield" in response.data


def test_form_required_local_message(app, sqlalchemy_datastore):
    """ Test having a local message (not xlatable and not part of MSG_ config."""

    class MyLoginForm(LoginForm):
        myfield = StringField("My Custom Field", validators=[Required(message="hi")])

    app.config["SECURITY_LOGIN_FORM"] = MyLoginForm

    security = Security(datastore=sqlalchemy_datastore)
    security.init_app(app)

    client = app.test_client()

    response = client.post("/login", content_type="application/json")
    assert response.status_code == 400
    assert b"myfield" in response.data


@pytest.mark.babel(False)
def test_without_babel(client):
    response = client.get("/login")
    assert b"Login" in response.data


def test_no_email_sender(app):
    """ Verify that if SECURITY_EMAIL_SENDER is default
        (which is a local proxy) that send_mail picks up MAIL_DEFAULT_SENDER.
    """
    app.config["MAIL_DEFAULT_SENDER"] = "test@testme.com"

    class TestUser(object):
        def __init__(self, email):
            self.email = email

    security = Security()
    security.init_app(app)

    with app.app_context():
        user = TestUser("matt@lp.com")
        with app.mail.record_messages() as outbox:
            send_mail("Test Default Sender", user.email, "welcome", user=user)
        assert 1 == len(outbox)
        assert "test@testme.com" == outbox[0].sender


def test_xlation(app, client):
    app.config["BABEL_DEFAULT_LOCALE"] = "fr_FR"
    assert check_xlation(app, "fr_FR"), "You must run python setup.py compile_catalog"

    response = client.get("/login")
    assert b'<label for="password">Mot de passe</label>' in response.data
    response = authenticate(client)
    assert response.status_code == 302
    response = authenticate(client, follow_redirects=True)
    assert b"Bienvenue matt@lp.com" in response.data


def test_form_labels(app):
    app.config["BABEL_DEFAULT_LOCALE"] = "fr_FR"
    app.security = Security()
    app.security.init_app(app)
    assert check_xlation(app, "fr_FR"), "You must run python setup.py compile_catalog"

    with app.test_request_context():
        rform = RegisterForm()
        assert str(rform.password.label.text) == "Mot de passe"
        assert str(rform.password_confirm.label.text) == "Confirmer le mot de passe"
        assert str(rform.email.label.text) == "Adresse email"
        assert str(rform.submit.label.text) == "Inscription"

        form = LoginForm()
        assert str(form.password.label.text) == "Mot de passe"
        assert str(form.remember.label.text) == "Se souvenir de moi"
        assert str(form.email.label.text) == "Adresse email"
        assert str(form.submit.label.text) == "Connexion"

        form = ChangePasswordForm()
        assert str(form.password.label.text) == "Mot de passe"
        assert str(form.new_password.label.text) == "Nouveau mot de passe"
        assert str(form.new_password_confirm.label.text) == "Confirmer le mot de passe"
        assert str(form.submit.label.text) == "Changer le mot de passe"


@pytest.mark.changeable()
def test_per_request_xlate(app, client):
    from flask import request, session

    babel = app.extensions["babel"]

    @babel.localeselector
    def get_locale():
        # For a given session - set lang based on first request.
        # Honor explicit url request first
        if "lang" not in session:
            locale = request.args.get("lang", None)
            if not locale:
                locale = request.accept_languages.best
            if locale:
                session["lang"] = locale
        return session.get("lang", None).replace("-", "_")

    response = client.get("/login", headers=[("Accept-Language", "fr")])
    assert b'<label for="password">Mot de passe</label>' in response.data

    data = dict(email="matt@lp.com", password="", remember="y")
    response = client.post("/login", data=data, headers=[("Accept-Language", "fr")])
    assert response.status_code == 200

    # verify errors are xlated
    assert b"Merci d&#39;indiquer un mot de passe" in response.data

    # log in correctly - this should set locale in session
    data = dict(email="matt@lp.com", password="password", remember="y")
    response = client.post(
        "/login", data=data, headers=[("Accept-Language", "fr")], follow_redirects=True
    )
    assert response.status_code == 200

    # make sure further requests always get correct xlation w/o sending header
    response = client.get("/change", follow_redirects=True)
    assert response.status_code == 200
    assert b"Nouveau mot de passe" in response.data

    # try JSON
    data = '{"email": "matt@lp.com"}'
    response = client.post(
        "/change", data=data, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert response.jdata["response"]["errors"]["new_password"] == [
        "Merci d'indiquer un mot de passe"
    ]


"""
This cant work yet due to zxcvbn usage of gettext
def test_zxcvbn_xlate(app):
    class TestUser(object):
        def __init__(self, email):
            self.email = email

    app.config["BABEL_DEFAULT_LOCALE"] = "fr_FR"
    app.security = Security()
    app.security.init_app(app)
    assert check_xlation(app, "fr_FR"), "You must run python setup.py compile_catalog"

    with app.test_request_context():
        user = TestUser("jwag@notme.com")
        result = app.security._password_validator("simple", False, user=user)
        print(result)
"""


@pytest.mark.skipif(sys.version_info < (3, 0), reason="requires python3 or higher")
@pytest.mark.settings(password_check_breached="strict")
def test_breached(app):

    # partial response from: https://api.pwnedpasswords.com/range/07003
    pwned_response = "AF5A73CD3CBCFDCD12B0B68CB7930F3E888:2\r\n\
AFD8AA47E6FD782ADDC11D89744769F7354:2\r\n\
B04334E179537C975D0B3C72DA2E5B68E44:15\r\n\
B118F58C2373FDF97ACF93BD3339684D1EB:2\r\n\
B1ED5D27429EDF77EFD84F4EA9BDA5013FB:4\r\n\
B25C03CFBE4CBF19E0F4889711C9A488E5D:2\r\n\
B3902FD808DCA504AAAD30F3C14BD3ACE7C:10".encode(
        "utf-8"
    )

    app.security = Security()
    app.security.init_app(app)
    with app.test_request_context():
        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = (
                pwned_response
            )
            pbad = app.security._password_validator("flaskflask", False)
            assert len(pbad) == 1
            assert app.config["SECURITY_MSG_PASSWORD_BREACHED"][0] in pbad[0]


@pytest.mark.skipif(sys.version_info < (3, 0), reason="requires python3 or higher")
@pytest.mark.settings(
    password_check_breached="strict",
    password_breached_count=16,
    password_complexity_checker="zxcvbn",
)
def test_breached_cnt(app):

    # partial response from: https://api.pwnedpasswords.com/range/07003
    pwned_response = "AF5A73CD3CBCFDCD12B0B68CB7930F3E888:2\r\n\
AFD8AA47E6FD782ADDC11D89744769F7354:2\r\n\
B04334E179537C975D0B3C72DA2E5B68E44:15\r\n\
B118F58C2373FDF97ACF93BD3339684D1EB:2\r\n\
B1ED5D27429EDF77EFD84F4EA9BDA5013FB:4\r\n\
B25C03CFBE4CBF19E0F4889711C9A488E5D:2\r\n\
B3902FD808DCA504AAAD30F3C14BD3ACE7C:10".encode(
        "utf-8"
    )

    app.security = Security()
    app.security.init_app(app)
    with app.test_request_context():
        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = (
                pwned_response
            )
            pbad = app.security._password_validator("flaskflask", True)
            # Still weak password, just not pwned enough. Should fail complexity
            assert len(pbad) == 1
            assert "Repeats like" in pbad[0]


@pytest.mark.skip
@pytest.mark.settings(password_check_breached="strict")
def test_breached_real(app):
    """ Actually go out to internet.. """

    app.security = Security()
    app.security.init_app(app)
    with app.test_request_context():
        pbad = app.security._password_validator("flaskflask", True)
        assert len(pbad) == 1
        assert app.config["SECURITY_MSG_PASSWORD_BREACHED"][0] in pbad[0]


def test_json_error_response_string():
    """ Unit test for correct response when a string is given. """
    error_msg = "This is an error!"
    response = json_error_response(errors=error_msg)
    assert "error" in response
    assert "errors" not in response
    assert response["error"] == error_msg


def test_json_error_response_dict():
    """ Unit test for correct response when a dict is given. """
    error_msg = {
        "e-mail": "The e-mail address is already in the system.",
        "name": "The name is too long.",
    }
    response = json_error_response(errors=error_msg)
    assert "errors" in response
    assert "error" not in response
    assert response["errors"] == error_msg


def test_json_error_response_typeerror():
    """ Unit test for checking for error raising. """
    error_msg = ("tuple",)
    with pytest.raises(TypeError):
        json_error_response(errors=error_msg)


def test_method_view(app, client):
    # auth_required with flask method view
    from flask.views import MethodView
    from flask import render_template_string

    class MyView(MethodView):
        decorators = [auth_required("token", "session")]

        def get(self):
            return render_template_string("Hi view")

    myview = MyView.as_view("myview")

    app.add_url_rule("/myview", view_func=myview, methods=["GET"])

    response = client.get("/myview", follow_redirects=False)
    # should require login
    assert response.status_code == 302
    assert "/login" in response.location

    authenticate(client)
    response = client.get("/myview")
    assert response.status_code == 200
    assert b"Hi view" in response.data
