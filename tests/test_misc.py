"""
    test_misc
    ~~~~~~~~~~~

    Lots of tests

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from datetime import timedelta
import hashlib
from unittest import mock
import re
import os.path
import pkg_resources
import sys
import time

import pytest

from tests.test_utils import (
    authenticate,
    capture_flashes,
    capture_reset_password_requests,
    check_xlation,
    init_app_with_options,
    json_authenticate,
    logout,
    populate_data,
)

from flask import abort, request, Response
from flask_security import Security
from flask_security.forms import (
    ChangePasswordForm,
    ConfirmRegisterForm,
    EmailField,
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
from flask_security import auth_required, roles_required
from flask_security.utils import (
    encode_string,
    json_error_response,
    get_request_attr,
    hash_data,
    send_mail,
    uia_phone_mapper,
    verify_hash,
)


@pytest.mark.recoverable()
def test_my_mail_util(app, sqlalchemy_datastore):
    from flask_security import MailUtil

    class MyMailUtil(MailUtil):
        def send_mail(
            self, template, subject, recipient, sender, body, html, user, **kwargs
        ):
            assert template == "reset_instructions"
            assert subject == app.config["SECURITY_EMAIL_SUBJECT_PASSWORD_RESET"]
            assert recipient == "matt@lp.com"
            assert user.email == "matt@lp.com"
            assert sender == "no-reply@localhost"
            assert isinstance(sender, str)

    init_app_with_options(
        app, sqlalchemy_datastore, **{"security_args": {"mail_util_cls": MyMailUtil}}
    )

    client = app.test_client()
    client.post("/reset", data=dict(email="matt@lp.com"))


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
        email = EmailField("My Login Email Address Field")

    class MyRegisterForm(RegisterForm):
        email = EmailField("My Register Email Address Field")

    class MyForgotPasswordForm(ForgotPasswordForm):
        email = EmailField(
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
        email = EmailField("My Register Email Address Field")

    class MySendConfirmationForm(SendConfirmationForm):
        email = EmailField("My Send Confirmation Email Address Field")

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
        email = EmailField("My Passwordless Email Address Field")

    app.security = Security(
        app,
        datastore=sqlalchemy_datastore,
        passwordless_login_form=MyPasswordlessLoginForm,
    )

    client = app.test_client()

    response = client.get("/login")
    assert b"My Passwordless Email Address Field" in response.data


@pytest.mark.parametrize("logout_methods", (["GET", "POST"], ["GET"], ["POST"]))
def test_logout_methods(app, sqlalchemy_datastore, logout_methods):
    init_app_with_options(
        app, sqlalchemy_datastore, **{"SECURITY_LOGOUT_METHODS": logout_methods}
    )

    client = app.test_client()

    authenticate(client)

    response = client.get("/logout", follow_redirects=True)

    if "GET" in logout_methods:
        assert response.status_code == 200

        authenticate(client)

    else:
        assert response.status_code == 405  # method not allowed

    response = client.post("/logout", follow_redirects=True)

    if "POST" in logout_methods:
        assert response.status_code == 200

    else:
        assert response.status_code == 405  # method not allowed


def test_logout_methods_none(app, sqlalchemy_datastore):
    init_app_with_options(
        app, sqlalchemy_datastore, **{"SECURITY_LOGOUT_METHODS": None}
    )

    client = app.test_client()

    authenticate(client)

    response = client.get("/logout", follow_redirects=True)

    assert response.status_code == 404

    response = client.post("/logout", follow_redirects=True)

    assert response.status_code == 404


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
@pytest.mark.parametrize("data", ["hellö", b"hello"])
def test_legacy_hash(in_app_context, data):
    legacy_hash = hashlib.md5(encode_string(data)).hexdigest()
    new_hash = hash_data(data)
    assert legacy_hash == new_hash


def test_hash_data(in_app_context):
    data = hash_data(b"hello")
    assert isinstance(data, str)
    data = hash_data("hellö")
    assert isinstance(data, str)


def test_verify_hash(in_app_context):
    data = hash_data("hellö")
    assert verify_hash(data, "hellö") is True
    assert verify_hash(data, "hello") is False

    legacy_data = hashlib.md5(encode_string("hellö")).hexdigest()
    assert verify_hash(legacy_data, "hellö") is True
    assert verify_hash(legacy_data, "hello") is False


@pytest.mark.settings(
    password_salt="öööööööööööööööööööööööööööööööööö", password_hash="bcrypt"
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
    # This isn't really 'without' babel - it is without initializing babel
    with pytest.raises(ValueError):
        client.get("/login")


def test_no_email_sender(app):
    """Verify that if SECURITY_EMAIL_SENDER is default
    (which is a local proxy) that send_mail picks up MAIL_DEFAULT_SENDER.
    """
    app.config["MAIL_DEFAULT_SENDER"] = "test@testme.com"

    class TestUser:
        def __init__(self, email):
            self.email = email

    security = Security()
    security.init_app(app)

    with app.app_context():
        app.try_trigger_before_first_request_functions()
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


def test_myxlation(app, sqlalchemy_datastore, pytestconfig):
    # Test changing a single MSG and having an additional translation dir

    i18n_dirname = [
        pkg_resources.resource_filename("flask_security", "translations"),
        os.path.join(pytestconfig.rootdir, "tests/translations"),
    ]
    init_app_with_options(
        app, sqlalchemy_datastore, **{"SECURITY_I18N_DIRNAME": i18n_dirname}
    )

    app.config["BABEL_DEFAULT_LOCALE"] = "fr_FR"
    assert check_xlation(app, "fr_FR"), "You must run python setup.py compile_catalog"

    app.config["SECURITY_MSG_INVALID_PASSWORD"] = ("Password no-worky", "error")

    client = app.test_client()
    response = client.post("/login", data=dict(email="matt@lp.com", password="forgot"))
    assert b"Passe - no-worky" in response.data


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
    # make sure template contents get xlated (not just form).
    assert b"<h1>Connexion</h1>" in response.data

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
    assert b"<h1>Changer de mot de passe</h1>" in response.data

    # try JSON
    response = client.post(
        "/change",
        json=dict(email="matt@lp.com"),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json["response"]["errors"]["new_password"] == [
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
        pbad, pnorm = app.security._password_util.validate("simple", False, user=user)
        print(pbad)
"""


@pytest.mark.skipif(sys.version_info < (3, 0), reason="requires python3 or higher")
@pytest.mark.settings(password_check_breached="strict")
def test_breached(app):

    # partial response from: https://api.pwnedpasswords.com/range/07003
    pwned_response = b"AF5A73CD3CBCFDCD12B0B68CB7930F3E888:2\r\n\
AFD8AA47E6FD782ADDC11D89744769F7354:2\r\n\
B04334E179537C975D0B3C72DA2E5B68E44:15\r\n\
B118F58C2373FDF97ACF93BD3339684D1EB:2\r\n\
B1ED5D27429EDF77EFD84F4EA9BDA5013FB:4\r\n\
B25C03CFBE4CBF19E0F4889711C9A488E5D:2\r\n\
B3902FD808DCA504AAAD30F3C14BD3ACE7C:10"

    app.security = Security()
    app.security.init_app(app)
    with app.test_request_context():
        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = (
                pwned_response
            )
            pbad, pnorm = app.security._password_util.validate("flaskflask", False)
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
    pwned_response = b"AF5A73CD3CBCFDCD12B0B68CB7930F3E888:2\r\n\
AFD8AA47E6FD782ADDC11D89744769F7354:2\r\n\
B04334E179537C975D0B3C72DA2E5B68E44:15\r\n\
B118F58C2373FDF97ACF93BD3339684D1EB:2\r\n\
B1ED5D27429EDF77EFD84F4EA9BDA5013FB:4\r\n\
B25C03CFBE4CBF19E0F4889711C9A488E5D:2\r\n\
B3902FD808DCA504AAAD30F3C14BD3ACE7C:10"

    app.security = Security()
    app.security.init_app(app)
    with app.test_request_context():
        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = (
                pwned_response
            )
            pbad, pnorm = app.security._password_util.validate("flaskflask", True)
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
        pbad, pnorm = app.security._password_util.validate("flaskflask", True)
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


def test_phone_util_override(app):
    class MyPhoneUtil:
        def __init__(self, app):
            pass

        def validate_phone_number(self, input_data):
            return "call-me"

        def get_canonical_form(self, input_data):
            return "very-canonical"

    app.security = Security()
    app.security.init_app(app, phone_util_cls=MyPhoneUtil)

    with app.app_context():
        assert uia_phone_mapper("55") == "very-canonical"


def test_authn_freshness(app, client, get_message):
    """ Test freshness using default reauthn_handler """

    @auth_required(within=30, grace=0)
    def myview():
        return Response(status=200)

    @auth_required(within=0.001, grace=0)
    def myspecialview():
        return Response(status=200)

    app.add_url_rule("/myview", view_func=myview, methods=["GET"])
    app.add_url_rule("/myspecialview", view_func=myspecialview, methods=["GET"])
    authenticate(client)

    # This should work and not be redirected
    response = client.get("/myview", follow_redirects=False)
    assert response.status_code == 200

    # This should require additional authn and redirect to verify
    time.sleep(0.1)
    with capture_flashes() as flashes:
        response = client.get("/myspecialview", follow_redirects=False)
        assert response.status_code == 302
        assert (
            response.location
            == "http://localhost/verify?next=http%3A%2F%2Flocalhost%2Fmyspecialview"
        )
    assert flashes[0]["category"] == "error"
    assert flashes[0]["message"].encode("utf-8") == get_message(
        "REAUTHENTICATION_REQUIRED"
    )

    # Test json error response
    response = client.get("/myspecialview", headers={"accept": "application/json"})
    assert response.status_code == 401
    assert response.json["response"]["error"].encode("utf-8") == get_message(
        "REAUTHENTICATION_REQUIRED"
    )


def test_authn_freshness_handler(app, client, get_message):
    """ Test with our own handler """

    @app.security.reauthn_handler
    def my_reauthn(within, grace, headers=None):
        assert within == timedelta(minutes=30) or timedelta(minutes=0.001)
        if app.security._want_json(request):
            payload = json_error_response(errors="Oh No")
            return app.security._render_json(payload, 401, headers, None)
        abort(500)

    @auth_required(within=30, grace=0)
    def myview():
        return Response(status=200)

    @auth_required(within=0.001, grace=0)
    def myspecialview():
        return Response(status=200)

    app.add_url_rule("/myview", view_func=myview, methods=["GET"])
    app.add_url_rule("/myspecialview", view_func=myspecialview, methods=["GET"])
    authenticate(client)

    # This should work and not be redirected
    response = client.get("/myview", follow_redirects=False)
    assert response.status_code == 200

    # This should require additional authn
    time.sleep(0.1)
    response = client.get("/myspecialview", follow_redirects=False)
    assert response.status_code == 500

    # Test json error response
    response = client.get("/myspecialview", headers={"accept": "application/json"})
    assert response.status_code == 401
    assert response.json["response"]["error"] == "Oh No"


def test_authn_freshness_callable(app, client, get_message):
    @auth_required(within=lambda: timedelta(minutes=30))
    def myview():
        return Response(status=200)

    app.add_url_rule("/myview", view_func=myview, methods=["GET"])
    authenticate(client)

    # This should work and not be redirected
    response = client.get("/myview", follow_redirects=False)
    assert response.status_code == 200


def test_authn_freshness_grace(app, client, get_message):
    # Test that grace override within.
    @auth_required(within=lambda: timedelta(minutes=30), grace=10)
    def myview():
        return Response(status=200)

    @auth_required(within=0.001, grace=lambda: timedelta(minutes=10))
    def myspecialview():
        return Response(status=200)

    app.add_url_rule("/myview", view_func=myview, methods=["GET"])
    app.add_url_rule("/myspecialview", view_func=myspecialview, methods=["GET"])
    authenticate(client)

    # This should work and not be redirected
    response = client.get("/myview", follow_redirects=False)
    assert response.status_code == 200

    # This should NOT require additional authn
    time.sleep(0.1)
    response = client.get("/myspecialview", follow_redirects=False)
    assert response.status_code == 200


def test_authn_freshness_nc(app, client_nc, get_message):
    # If don't send session cookie - then freshness always fails
    @auth_required(within=30)
    def myview():
        return Response(status=200)

    app.add_url_rule("/myview", view_func=myview, methods=["GET"])

    response = json_authenticate(client_nc)
    token = response.json["response"]["user"]["authentication_token"]
    h = {"Authentication-Token": token}

    # This should fail - should be a redirect
    response = client_nc.get("/myview", headers=h, follow_redirects=False)
    assert response.status_code == 302
    assert (
        response.location
        == "http://localhost/verify?next=http%3A%2F%2Flocalhost%2Fmyview"
    )


def test_verify_fresh(app, client, get_message):
    # Hit a fresh-required endpoint and walk through verify
    authenticate(client)

    with capture_flashes() as flashes:
        response = client.get("/fresh", follow_redirects=True)
        assert b"Please Enter Your Password" in response.data
    assert flashes[0]["category"] == "error"
    assert flashes[0]["message"].encode("utf-8") == get_message(
        "REAUTHENTICATION_REQUIRED"
    )
    form_response = response.data.decode("utf-8")
    matcher = re.match(
        r'.*action="([^"]*)".*', form_response, re.IGNORECASE | re.DOTALL
    )
    verify_url = matcher.group(1)

    response = client.get(verify_url)
    assert b"Please Enter Your Password" in response.data

    response = client.post(
        verify_url, data=dict(password="not my password"), follow_redirects=False
    )
    assert b"Please Enter Your Password" in response.data

    response = client.post(
        verify_url, data=dict(password="password"), follow_redirects=False
    )
    assert response.location == "http://localhost/fresh"

    # should be fine now
    response = client.get("/fresh", follow_redirects=True)
    assert b"Fresh Only" in response.data


def test_verify_fresh_json(app, client, get_message):
    # Hit a fresh-required endpoint and walk through verify
    authenticate(client)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    response = client.get("/fresh", headers=headers)
    assert response.status_code == 401
    assert response.json["response"]["reauth_required"]

    response = client.get("/verify")
    assert b"Please Enter Your Password" in response.data

    response = client.post(
        "/verify", json=dict(password="not my password"), headers=headers
    )
    assert response.status_code == 400

    response = client.post("/verify", json=dict(password="password"), headers=headers)
    assert response.status_code == 200

    # should be fine now
    response = client.get("/fresh", headers=headers)
    assert response.status_code == 200
    assert response.json["title"] == "Fresh Only"


@pytest.mark.changeable()
def test_verify_pwd_json(app, client, get_message):
    # Make sure verify accepts a normalized and original password.
    authenticate(client)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    data = dict(
        password="password",
        new_password="new strong password\N{ROMAN NUMERAL ONE}",
        new_password_confirm="new strong password\N{ROMAN NUMERAL ONE}",
    )
    response = client.post(
        "/change",
        json=data,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200

    response = client.post(
        "/verify",
        json=dict(password="new strong password\N{ROMAN NUMERAL ONE}"),
        headers=headers,
    )
    assert response.status_code == 200

    response = client.post(
        "/verify",
        json=dict(password="new strong password\N{LATIN CAPITAL LETTER I}"),
        headers=headers,
    )
    assert response.status_code == 200


@pytest.mark.settings(verify_url="/auth/")
def test_verify_next(app, client, get_message):
    authenticate(client)
    response = client.post(
        "/auth/?next=http://localhost/mynext",
        data=dict(password="password"),
        follow_redirects=False,
    )
    assert response.location == "http://localhost/mynext"

    response = client.post(
        "/auth/?next=http%3A%2F%2F127.0.0.1%3A5000%2Fdashboard%2Fsettings%2F",
        data=dict(password="password"),
        follow_redirects=False,
        base_url="http://127.0.0.1:5000",
    )
    assert response.location == "http://127.0.0.1:5000/dashboard/settings/"


def test_direct_decorator(app, client, get_message):
    """ Test/show calling the auth_required decorator directly """
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    def myview():
        return roles_required("author")(domyview)()

    def domyview():
        return Response(status=200)

    app.add_url_rule("/myview", view_func=myview, methods=["GET"])

    authenticate(client)
    response = client.get("/myview", headers=headers)
    assert response.status_code == 403

    logout(client)

    authenticate(client, email="jill@lp.com")
    response = client.get("/myview", headers=headers)
    assert response.status_code == 200


def test_authn_via(app, client, get_message):
    """ Test that we get correct fs_authn_via set in request """

    @auth_required(within=30, grace=0)
    def myview():
        assert get_request_attr("fs_authn_via") == "session"
        return Response(status=200)

    app.add_url_rule("/myview", view_func=myview, methods=["GET"])
    authenticate(client)

    # This should work and not be redirected
    response = client.get("/myview", follow_redirects=False)
    assert response.status_code == 200


def test_post_security_with_application_root(app, sqlalchemy_datastore):
    init_app_with_options(app, sqlalchemy_datastore, **{"APPLICATION_ROOT": "/root"})
    client = app.test_client()

    response = client.post(
        "/login", data=dict(email="matt@lp.com", password="password")
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "http://localhost/root"

    response = client.get("/logout")
    assert response.status_code == 302
    assert response.headers["Location"] == "http://localhost/root"


def test_post_security_with_application_root_and_views(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "APPLICATION_ROOT": "/root",
            "SECURITY_POST_LOGIN_VIEW": "/post_login",
            "SECURITY_POST_LOGOUT_VIEW": "/post_logout",
        }
    )
    client = app.test_client()

    response = client.post(
        "/login", data=dict(email="matt@lp.com", password="password")
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "http://localhost/post_login"

    response = client.get("/logout")
    assert response.status_code == 302
    assert response.headers["Location"] == "http://localhost/post_logout"
