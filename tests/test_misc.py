"""
    test_misc
    ~~~~~~~~~~~

    Lots of tests

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2023 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from datetime import timedelta
import hashlib
from unittest import mock
import re
import os.path
import sys
import time
import typing as t

import pytest

from wtforms.validators import DataRequired, Length

from tests.test_utils import (
    authenticate,
    capture_flashes,
    capture_reset_password_requests,
    check_xlation,
    get_csrf_token,
    init_app_with_options,
    json_authenticate,
    logout,
    populate_data,
    reset_fresh,
)
from tests.test_webauthn import HackWebauthnUtil, reg_2_keys

from flask import Flask, abort, request, Response
from flask_security import Security
from flask_security.forms import (
    ChangePasswordForm,
    ConfirmRegisterForm,
    EmailField,
    EmailValidation,
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
    valid_user_email,
)
from flask_security import auth_required, roles_required
from flask_security.utils import (
    base_render_json,
    encode_string,
    json_error_response,
    get_request_attr,
    hash_data,
    send_mail,
    uia_email_mapper,
    uia_phone_mapper,
    validate_redirect_url,
    verify_hash,
)

if t.TYPE_CHECKING:  # pragma: no cover
    from flask.testing import FlaskClient


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
    app.security = Security(
        app, datastore=sqlalchemy_datastore, register_blueprint=False
    )
    client = app.test_client()
    response = client.get("/login")
    assert response.status_code == 404


@pytest.mark.registerable()
@pytest.mark.recoverable()
@pytest.mark.changeable()
@pytest.mark.settings(
    USER_IDENTITY_ATTRIBUTES=[
        {"email": {"mapper": uia_email_mapper}},
        {"username": {"mapper": lambda x: x}},
    ]
)
def test_basic_custom_forms(app, sqlalchemy_datastore):
    class MyLoginForm(LoginForm):
        username = StringField("My Login Username Field")

    class MyRegisterForm(RegisterForm):
        email = EmailField("My Register Email Address Field")

    class MyForgotPasswordForm(ForgotPasswordForm):
        email = EmailField(
            "My Forgot Email Address Field",
            validators=[email_required, EmailValidation(verify=True), valid_user_email],
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
    assert b"My Login Username Field" in response.data

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
            **{"SECURITY_TWO_FACTOR": True, "SECURITY_TWO_FACTOR_ENABLED_METHODS": []},
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
        },
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


@pytest.mark.filterwarnings(
    "ignore:.*'unauthorized_handler' has been replaced.*:DeprecationWarning"
)
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


def test_custom_form_instantiator(app, client, get_message):
    # Test application form instantiation.
    # This is using the form factory pattern.
    # Note in this case - Flask-Security doesn't even know the form class name.
    from flask_security import FormInfo

    class FormInstantiator:
        def __init__(self, myservice):
            self.myservice = myservice

        def instantiator(self, form_name, form_cls, *args, **kwargs):
            if form_name == "login_form":
                return MyLoginForm(*args, service=self.myservice, **kwargs)
            raise ValueError("Unknown Form")

    class MyLoginForm(LoginForm):
        def __init__(self, *args, service=None, **kwargs):
            super().__init__(*args, **kwargs)
            self.myservice = service

        def validate(self, **kwargs: t.Any) -> bool:
            if not super().validate(**kwargs):  # pragma: no cover
                return False
            if not self.myservice(self.email.data):
                self.email.errors.append("Not happening")
                return False
            return True

    def login_checker(email):
        return True if email == "matt@lp.com" else False

    fi = FormInstantiator(login_checker)
    app.security.set_form_info("login_form", FormInfo(fi.instantiator))

    response = authenticate(client, follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data
    logout(client)

    # Try a normally legit user - but our service denies it
    response = authenticate(client, email="joe@lp.com")
    assert b"Not happening" in response.data


def test_custom_form_instantiator2(app, client, get_message):
    # Test application form instantiation.
    # This is using the form clone pattern.
    # Note in this case - Flask-Security doesn't even know the form class name.
    app.config["WTF_CSRF_ENABLED"] = True
    from flask_security import FormInfo

    class MyLoginForm(LoginForm):
        def __init__(self, *args, service=None, **kwargs):
            super().__init__(*args, **kwargs)
            self.myservice = service

        def instantiator(self, form_name, form_cls, *args, **kwargs):
            return MyLoginForm(*args, service=self.myservice, **kwargs)

        def validate(self, **kwargs: t.Any) -> bool:
            if not super().validate(**kwargs):  # pragma: no cover
                return False
            if not self.myservice(self.email.data):
                self.email.errors.append("Not happening")
                return False
            return True

    def login_checker(email):
        return True if email == "matt@lp.com" else False

    with app.test_request_context():
        fi = MyLoginForm(formdata=None, service=login_checker)
    app.security.set_form_info("login_form", FormInfo(fi.instantiator))

    csrf_token = get_csrf_token(client)
    response = client.post(
        "/login",
        data=dict(email="matt@lp.com", password="password", csrf_token=csrf_token),
        follow_redirects=True,
    )
    assert b"Welcome matt@lp.com" in response.data
    logout(client)

    # Try a normally legit user - but our service denies it
    csrf_token = get_csrf_token(client)
    response = client.post(
        "/login",
        data=dict(email="joe@lp.com", password="password", csrf_token=csrf_token),
    )
    assert b"Not happening" in response.data


def test_custom_form_setting(app, sqlalchemy_datastore):
    from flask_security import FormInfo

    security = Security(app=app, datastore=sqlalchemy_datastore)
    with pytest.raises(ValueError) as vex:
        security.set_form_info("mylogin_form", FormInfo())
    assert "Unknown form name mylogin_form" == str(vex.value)
    with pytest.raises(ValueError) as vex:
        security.set_form_info("login_form", FormInfo())
    assert "form class must be provided" in str(vex.value)


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
    """Test having a local message (not xlatable and not part of MSG_ config."""

    msg = "hi! did you forget me?"

    class MyLoginForm(LoginForm):
        myfield = StringField("My Custom Field", validators=[Required(message=msg)])

    app.config["SECURITY_LOGIN_FORM"] = MyLoginForm

    security = Security(datastore=sqlalchemy_datastore)
    security.init_app(app)

    client = app.test_client()

    response = client.post("/login", content_type="application/json")
    assert response.status_code == 400
    assert b"myfield" in response.data
    assert msg.encode("utf-8") in response.data
    # WTforms 2.x incorrectly catches ValueError and sets that as the form error.
    # Our config_value routine raises ValueError for missing config items..
    assert b"Key" not in response.data


def test_without_babel(app, client):
    # Test if babel modules exist but we don't init babel - things still work
    app.config["BABEL_DEFAULT_LOCALE"] = "fr_FR"
    response = client.get("/login")
    assert response.status_code == 200


def test_no_email_sender(app, sqlalchemy_datastore):
    """Verify that if SECURITY_EMAIL_SENDER is default
    (which is a local proxy) that send_mail picks up MAIL_DEFAULT_SENDER.
    """
    app.config["MAIL_DEFAULT_SENDER"] = "test@testme.com"

    class TestUser:
        def __init__(self, email):
            self.email = email

    security = Security()
    security.init_app(app, sqlalchemy_datastore)

    with app.app_context():
        user = TestUser("matt@lp.com")
        send_mail("Test Default Sender", user.email, "welcome", user=user)
        outbox = app.mail.outbox
        assert 1 == len(outbox)
        assert "test@testme.com" == outbox[0].from_email


def test_sender_tuple(app, sqlalchemy_datastore):
    """Verify that if sender is a (name, address) tuple,
    in the received email sender is properly formatted as "name <address>"
    Flask-Mail takes tuples - Flask-Mailman takes them - however the
    local-mem backend doesn't format them correctly (SMTP backend doesn't work either?)
    """
    app.config["MAIL_DEFAULT_SENDER"] = ("Test User", "test@testme.com")

    class TestUser:
        def __init__(self, email):
            self.email = email

    security = Security()
    security.init_app(app, sqlalchemy_datastore)

    with app.app_context():
        user = TestUser("matt@lp.com")
        send_mail("Test Tuple Sender", user.email, "welcome", user=user)
        outbox = app.mail.outbox
        assert 1 == len(outbox)
        assert outbox[0].from_email == "Test User <test@testme.com>"


def test_send_mail_context(app, sqlalchemy_datastore):
    """Test full context sent to MailUtil/send_mail"""
    app.config["MAIL_DEFAULT_SENDER"] = "test@testme.com"
    app.security = Security()
    app.security.init_app(app, sqlalchemy_datastore)

    class TestUser:
        def __init__(self, email):
            self.email = email

    @app.security.mail_context_processor
    def mail():
        return {"foo": "bar-mail"}

    with app.app_context():
        user = TestUser("matt@lp.com")
        send_mail("Test Default Sender", user.email, "welcome", user=user)
        outbox = app.mail.outbox
        assert 1 == len(outbox)
        assert "test@testme.com" == outbox[0].from_email
        matcher = re.match(
            r".*ExtraContext:(\S+).*", outbox[0].body, re.IGNORECASE | re.DOTALL
        )
        assert matcher.group(1) == "bar-mail"


@pytest.mark.babel()
@pytest.mark.app_settings(babel_default_locale="fr_FR")
def test_xlation(app, client):
    assert check_xlation(app, "fr_FR"), "You must run python setup.py compile_catalog"

    response = client.get("/login")
    assert b'<label for="password">Mot de passe</label>' in response.data
    response = authenticate(client)
    assert response.status_code == 302
    response = authenticate(client, follow_redirects=True)
    assert b"Bienvenue matt@lp.com" in response.data


@pytest.mark.babel()
@pytest.mark.app_settings(babel_default_locale="fr_FR")
def test_myxlation(app, sqlalchemy_datastore, pytestconfig):
    # Test changing a single MSG and having an additional translation dir
    # Flask-BabelEx doesn't support lists of directories..
    pytest.importorskip("flask_babel")

    i18n_dirname = [
        "builtin",
        os.path.join(pytestconfig.rootdir, "tests/translations"),
    ]
    init_app_with_options(
        app, sqlalchemy_datastore, **{"SECURITY_I18N_DIRNAME": i18n_dirname}
    )

    assert check_xlation(app, "fr_FR"), "You must run python setup.py compile_catalog"

    app.config["SECURITY_MSG_INVALID_PASSWORD"] = ("Password no-worky", "error")

    client = app.test_client()
    response = client.post("/login", data=dict(email="matt@lp.com", password="forgot"))
    assert b"Passe - no-worky" in response.data


@pytest.mark.babel()
@pytest.mark.app_settings(babel_default_locale="fr_FR")
def test_myxlation_complete(app, sqlalchemy_datastore, pytestconfig):
    # Test having own translations and not using builtin.
    pytest.importorskip("flask_babel")
    i18n_dirname = [
        os.path.join(pytestconfig.rootdir, "tests/translations"),
    ]
    init_app_with_options(
        app, sqlalchemy_datastore, **{"SECURITY_I18N_DIRNAME": i18n_dirname}
    )

    assert check_xlation(app, "fr_FR"), "You must run python setup.py compile_catalog"

    app.config["SECURITY_MSG_INVALID_PASSWORD"] = ("Password no-worky", "error")

    client = app.test_client()
    response = client.post("/login", data=dict(email="matt@lp.com", password="forgot"))
    assert b"Passe - no-worky" in response.data


@pytest.mark.babel()
@pytest.mark.app_settings(babel_default_locale="fr_FR")
def test_form_labels(app, sqlalchemy_datastore):
    app.security = Security()
    app.security.init_app(app, sqlalchemy_datastore)
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


@pytest.mark.babel()
@pytest.mark.app_settings(babel_default_locale="fr_FR")
def test_wtform_xlation(app, sqlalchemy_datastore):
    # Make sure wtform xlations work
    class MyLoginForm(LoginForm):
        fixed_length = StringField(
            "FixedLength", validators=[DataRequired(), Length(3, 3)]
        )

    app.security = Security()
    app.security.init_app(app, datastore=sqlalchemy_datastore, login_form=MyLoginForm)
    assert check_xlation(app, "fr_FR"), "You must run python setup.py compile_catalog"

    client = app.test_client()
    response = client.get("/login")
    assert b'<label for="password">Mot de passe</label>' in response.data
    data = dict(
        email="matt@lp.com", password="", remember="y", fixed_length="waytoolong"
    )
    response = client.post(
        "/login", json=data, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400
    flerror = response.json["response"]["field_errors"]["fixed_length"][0]
    # This is completely dependent on WTforms translations....
    assert (
        flerror == "Le doit contenir exactement 3 caractères."
        or flerror == "Le champ doit contenir exactement 3 caractères."
    )


@pytest.mark.changeable()
@pytest.mark.babel()
def test_per_request_xlate(app, client):
    from flask import request, session

    babel = app.extensions["babel"]

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

    babel.locale_selector_func = get_locale
    babel.locale_selector = get_locale  # Flask-Babel >= 3.0.0

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
    assert response.json["response"]["field_errors"]["new_password"] == [
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
def test_breached(app, sqlalchemy_datastore):
    # partial response from: https://api.pwnedpasswords.com/range/07003
    pwned_response = b"AF5A73CD3CBCFDCD12B0B68CB7930F3E888:2\r\n\
AFD8AA47E6FD782ADDC11D89744769F7354:2\r\n\
B04334E179537C975D0B3C72DA2E5B68E44:15\r\n\
B118F58C2373FDF97ACF93BD3339684D1EB:2\r\n\
B1ED5D27429EDF77EFD84F4EA9BDA5013FB:4\r\n\
B25C03CFBE4CBF19E0F4889711C9A488E5D:2\r\n\
B3902FD808DCA504AAAD30F3C14BD3ACE7C:10"

    app.security = Security()
    app.security.init_app(app, sqlalchemy_datastore)
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
def test_breached_cnt(app, sqlalchemy_datastore):
    # partial response from: https://api.pwnedpasswords.com/range/07003
    pwned_response = b"AF5A73CD3CBCFDCD12B0B68CB7930F3E888:2\r\n\
AFD8AA47E6FD782ADDC11D89744769F7354:2\r\n\
B04334E179537C975D0B3C72DA2E5B68E44:15\r\n\
B118F58C2373FDF97ACF93BD3339684D1EB:2\r\n\
B1ED5D27429EDF77EFD84F4EA9BDA5013FB:4\r\n\
B25C03CFBE4CBF19E0F4889711C9A488E5D:2\r\n\
B3902FD808DCA504AAAD30F3C14BD3ACE7C:10"

    app.security = Security()
    app.security.init_app(app, sqlalchemy_datastore)
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
def test_breached_real(app, sqlalchemy_datastore):
    """Actually go out to internet.."""

    app.security = Security()
    app.security.init_app(app, sqlalchemy_datastore)
    with app.test_request_context():
        pbad, pnorm = app.security._password_util.validate("flaskflask", True)
        assert len(pbad) == 1
        assert app.config["SECURITY_MSG_PASSWORD_BREACHED"][0] in pbad[0]


def test_json_error_response_string():
    """Unit test for correct response when a string is given."""
    error_msg = "This is an error!"
    response = json_error_response(errors=error_msg)
    assert "field_errors" not in response
    assert response["errors"][0] == error_msg


def test_json_error_response_dict():
    """Unit test for correct response when a dict is given."""
    error_msg = {
        "e-mail": ["The e-mail address is already in the system."],
        "name": ["The name is too long.", "Nice name"],
    }
    all_msgs = []
    [all_msgs.extend(m) for m in error_msg.values()]
    response = json_error_response(field_errors=error_msg)
    assert "errors" in response
    assert "field_errors" in response
    assert all(m in response["errors"] for m in all_msgs)


def test_json_error_response_typeerror():
    """Unit test for checking for error raising."""
    error_msg = ("tuple",)
    with pytest.raises(TypeError):
        json_error_response(errors=error_msg)


def test_json_form_errors(app, client):
    """Test wtforms form level errors are correctly sent via json"""
    with app.test_request_context():
        form = ChangePasswordForm()
        form.form_errors.append("I am an error")
        response = base_render_json(form)
        assert len(response.json["response"]["errors"]) == 1
        assert response.json["response"]["errors"][0] == "I am an error"


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


def test_phone_util_override(app, sqlalchemy_datastore):
    class MyPhoneUtil:
        def __init__(self, app):
            pass

        def validate_phone_number(self, input_data):
            return "call-me"

        def get_canonical_form(self, input_data):
            return "very-canonical"

    app.security = Security()
    app.security.init_app(app, sqlalchemy_datastore, phone_util_cls=MyPhoneUtil)

    with app.app_context():
        assert uia_phone_mapper("55") == "very-canonical"


def test_authn_freshness(
    app: "Flask", client: "FlaskClient", get_message: t.Callable[..., bytes]
) -> None:
    """Test freshness using default reauthn_handler"""

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
        assert "/verify?next=http://localhost/myspecialview" in response.location
    assert flashes[0]["category"] == "error"
    assert flashes[0]["message"].encode("utf-8") == get_message(
        "REAUTHENTICATION_REQUIRED"
    )

    # Test json error response
    response = client.get("/myspecialview", headers={"accept": "application/json"})
    assert response.status_code == 401
    assert response.json and response.json["response"]["errors"][0].encode(
        "utf-8"
    ) == get_message("REAUTHENTICATION_REQUIRED")


def test_authn_freshness_handler(app, client, get_message):
    """Test with our own handler"""

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
    assert response.json["response"]["errors"][0] == "Oh No"


def test_authn_freshness_callable(app, client, get_message):
    @auth_required(within=lambda: timedelta(minutes=30))
    def myview():
        return Response(status=200)

    app.add_url_rule("/myview", view_func=myview, methods=["GET"])
    authenticate(client)

    # This should work and not be redirected
    response = client.get("/myview", follow_redirects=False)
    assert response.status_code == 200


@pytest.mark.settings(url_prefix="/myprefix")
def test_default_authn_bp(app, client):
    """Test default reauthn handler with blueprint prefix"""

    @auth_required(within=1, grace=0)
    def myview():
        return Response(status=200)

    app.add_url_rule("/myview", view_func=myview, methods=["GET"])
    authenticate(client, endpoint="/myprefix/login")

    # This should require additional authn and redirect to verify
    reset_fresh(client, within=timedelta(minutes=1))
    response = client.get("/myview", follow_redirects=False)
    assert response.status_code == 302
    assert "/myprefix/verify?next=http://localhost/myview" in response.location


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
    assert "/verify?next=http://localhost/myview" in response.location


def test_verify_fresh(app, client, get_message):
    # Hit a fresh-required endpoint and walk through verify
    authenticate(client)
    reset_fresh(client, app.config["SECURITY_FRESHNESS"])

    with capture_flashes() as flashes:
        response = client.get("/fresh", follow_redirects=True)
        assert b"Please Reauthenticate" in response.data
    assert flashes[0]["category"] == "error"
    assert flashes[0]["message"].encode("utf-8") == get_message(
        "REAUTHENTICATION_REQUIRED"
    )
    form_response = response.data.decode("utf-8")
    matcher = re.match(
        r'.*action="([^"]*)".*', form_response, re.IGNORECASE | re.DOTALL
    )
    verify_url = matcher.group(1)

    reset_fresh(client, app.config["SECURITY_FRESHNESS"])
    response = client.get(verify_url)
    assert b"Please Reauthenticate" in response.data

    response = client.post(
        verify_url, data=dict(password="not my password"), follow_redirects=False
    )
    assert b"Please Reauthenticate" in response.data

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

    reset_fresh(client, app.config["SECURITY_FRESHNESS"])
    response = client.get("/fresh", headers=headers)
    assert response.status_code == 401
    assert response.json["response"]["reauth_required"]

    response = client.get("/verify")
    assert b"Please Reauthenticate" in response.data

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


@pytest.mark.webauthn()
@pytest.mark.settings(webauthn_util_cls=HackWebauthnUtil)
def test_verify_wan(app, client, get_message):
    # test get correct options when requiring a reauthentication and have wan keys
    # setup.
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    reg_2_keys(client)

    reset_fresh(client, app.config["SECURITY_FRESHNESS"])
    response = client.get("/fresh", headers=headers)
    assert response.status_code == 401
    assert response.json["response"]["reauth_required"]
    assert response.json["response"]["has_webauthn_verify_credential"]

    # the verify form should have the webauthn verify form attached
    response = client.get("verify")
    assert b'action="/wan-verify"' in response.data

    app.config["SECURITY_WAN_ALLOW_AS_VERIFY"] = None
    response = client.get("/fresh", headers=headers)
    assert response.status_code == 401
    assert response.json["response"]["reauth_required"]
    assert not response.json["response"]["has_webauthn_verify_credential"]

    # the verify form should NOT have the webauthn verify form attached
    response = client.get("verify")
    assert b'action="/wan-verify"' not in response.data


def test_direct_decorator(app, client, get_message):
    """Test/show calling the auth_required decorator directly"""
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
    """Test that we get correct fs_authn_via set in request"""

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
    assert "/root" in response.location

    response = client.get("/logout")
    assert response.status_code == 302
    assert "/root" in response.location


def test_post_security_with_application_root_and_views(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "APPLICATION_ROOT": "/root",
            "SECURITY_POST_LOGIN_VIEW": "/post_login",
            "SECURITY_POST_LOGOUT_VIEW": "/post_logout",
        },
    )
    client = app.test_client()

    response = client.post(
        "/login", data=dict(email="matt@lp.com", password="password")
    )
    assert response.status_code == 302
    assert "/post_login" in response.location

    response = client.get("/logout")
    assert response.status_code == 302
    assert "/post_logout" in response.location


@pytest.mark.settings(redirect_validate_mode="regex")
def test_validate_redirect(app, sqlalchemy_datastore):
    """
    Test various possible URLs that urlsplit() shows as relative but
    many browsers will interpret as absolute - and thus have a
    open-redirect vulnerability. Note this vulnerability only
    is viable if the application sets autocorrect_location_header = False
    """
    init_app_with_options(app, sqlalchemy_datastore)
    with app.test_request_context("http://localhost:5001/login"):
        assert not validate_redirect_url("\\\\\\github.com")
        assert not validate_redirect_url(" //github.com")
        assert not validate_redirect_url("\t//github.com")
        assert not validate_redirect_url("//github.com")  # this is normal urlsplit


def test_kwargs():
    import warnings

    warnings.simplefilter("error")
    with pytest.raises(DeprecationWarning):
        Security(myownkwarg="hi")


def test_nodatastore(app):
    with pytest.raises(ValueError):
        s = Security(app)
        s.init_app(app)


@pytest.mark.filterwarnings("ignore:.*Replacing login_manager.*:DeprecationWarning")
def test_reuse_security_object(sqlalchemy_datastore):
    # See: https://github.com/Flask-Middleware/flask-security/issues/518
    # Let folks re-use the Security object (mostly for testing).
    security = Security(datastore=sqlalchemy_datastore)

    app = Flask(__name__)
    app.response_class = Response
    app.debug = True
    app.config["SECRET_KEY"] = "secret"
    app.config["TESTING"] = True

    security.init_app(app)
    assert hasattr(app, "login_manager")

    app = Flask(__name__)
    app.response_class = Response
    app.debug = True
    app.config["SECRET_KEY"] = "secret"
    app.config["TESTING"] = True

    security.init_app(app)
    assert hasattr(app, "login_manager")


@pytest.mark.settings(static_folder_url="/mystatic/fs")
def test_static_url(app, sqlalchemy_datastore):
    from flask_security import url_for_security
    from flask import url_for

    init_app_with_options(app, sqlalchemy_datastore)
    with app.test_request_context("http://localhost:5001/login"):
        static_url = url_for_security("static", filename="js/webauthn.js")
        assert static_url == "/mystatic/fs/js/webauthn.js"

        static_url = url_for(".static", filename="js/webauthn.js")
        assert static_url == "/mystatic/fs/js/webauthn.js"


def test_multi_app(app, sqlalchemy_datastore):
    # test that 2 different app with 2 different FS
    # with USERNAME_ENABLE which dynamically changes the class definition
    app = Flask(__name__)
    app.response_class = Response
    app.debug = True
    app.config["SECRET_KEY"] = "secret"
    app.config["TESTING"] = True
    app.config["SECURITY_USERNAME_ENABLE"] = True

    security = Security(datastore=sqlalchemy_datastore)
    security.init_app(app)
    assert hasattr(security.forms["register_form"].cls, "username")
    assert "username" in security.user_identity_attributes[1].keys()

    app = Flask(__name__)
    app.response_class = Response
    app.debug = True
    app.config["SECRET_KEY"] = "secret"
    app.config["TESTING"] = True
    app.config["SECURITY_USERNAME_ENABLE"] = True

    security2 = Security(datastore=sqlalchemy_datastore)
    security2.init_app(app)

    assert hasattr(security2.forms["register_form"].cls, "username")
    assert "username" in security2.user_identity_attributes[1].keys()


@pytest.mark.registerable()
def test_login_email_whatever(app, client, get_message):
    # login, by default, shouldn't verify email address is deliverable..
    # register etc can/should do that.
    app.config["SECURITY_EMAIL_VALIDATOR_ARGS"] = {"check_deliverability": True}

    # register should fail since non-deliverable TLD
    data = dict(
        email="dude@me.mytld",
        password="awesome sunset",
    )
    response = client.post("/register", json=data)
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "INVALID_EMAIL_ADDRESS"
    )

    # login should work since we are just checking for identity
    response = client.post(
        "/login", data=dict(email="matt@lp.com", password="password")
    )
    assert response.status_code == 302
    assert "/" in response.location
