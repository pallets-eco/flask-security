"""
test_hashing
~~~~~~~~~~~~

hashing tests

:copyright: (c) 2019-2025 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.
"""

import timeit

import pytest
from pytest import raises
from tests.test_utils import authenticate, init_app_with_options
from passlib.hash import argon2, pbkdf2_sha256, django_pbkdf2_sha256, plaintext

from flask_security.core import _get_pwd_context, _get_hashing_context
from flask_security.utils import (
    hash_password,
    verify_password,
    get_hmac,
    verify_and_update_password,
)


def test_verify_password_double_hash_argon2(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "argon2",
            "SECURITY_PASSWORD_HASH_PASSLIB_OPTIONS": {"argon2__rounds": 1},
            "SECURITY_PASSWORD_SALT": "salty",
            "SECURITY_PASSWORD_SINGLE_HASH": False,
        },
    )
    with app.app_context():
        hashed_pwd = hash_password("pass")
        assert verify_password("pass", hashed_pwd)
        assert "t=1" in hashed_pwd

        # Verify double hash
        assert verify_password("pass", argon2.hash(get_hmac("pass")))


def test_verify_password_double_hash_bcrypt(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "bcrypt",
            "SECURITY_PASSWORD_SALT": "salty",
            "SECURITY_PASSWORD_SINGLE_HASH": False,
        },
    )
    with app.app_context():
        hashed_pwd = hash_password("pass")
        assert verify_password("pass", hashed_pwd)
        assert hashed_pwd.startswith("$2")


def test_verify_password_single_hash(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "argon2",
            "SECURITY_PASSWORD_HASH_PASSLIB_OPTIONS": {"argon2__rounds": 1},
            "SECURITY_PASSWORD_SALT": None,
            "SECURITY_PASSWORD_SINGLE_HASH": True,
        },
    )
    with app.app_context():
        assert verify_password("pass", hash_password("pass"))


def test_verify_password_single_hash_list(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "argon2",
            "SECURITY_PASSWORD_HASH_PASSLIB_OPTIONS": {"argon2__rounds": 1},
            "SECURITY_PASSWORD_SALT": "salty",
            "SECURITY_PASSWORD_SINGLE_HASH": ["django_pbkdf2_sha256", "plaintext"],
            "SECURITY_PASSWORD_SCHEMES": [
                "argon2",
                "pbkdf2_sha256",
                "django_pbkdf2_sha256",
                "plaintext",
            ],
        },
    )
    with app.app_context():
        # double hash
        assert verify_password("pass", hash_password("pass"))
        assert verify_password("pass", pbkdf2_sha256.hash(get_hmac("pass")))
        # single hash
        assert verify_password("pass", django_pbkdf2_sha256.hash("pass"))
        assert verify_password("pass", plaintext.hash("pass"))


def test_verify_password_backward_compatibility(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "argon2",
            "SECURITY_PASSWORD_HASH_PASSLIB_OPTIONS": {"argon2__rounds": 1},
            "SECURITY_PASSWORD_SINGLE_HASH": False,
            "SECURITY_PASSWORD_SCHEMES": ["argon2", "plaintext"],
        },
    )
    with app.app_context():
        # double hash
        assert verify_password("pass", hash_password("pass"))
        # single hash
        assert verify_password("pass", plaintext.hash("pass"))


def test_login_with_bcrypt_enabled(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "bcrypt",
            "SECURITY_PASSWORD_HASH_PASSLIB_OPTIONS": {
                "bcrypt__rounds": 4,  # minimum so test is faster
            },
            "SECURITY_PASSWORD_SALT": "salty",
            "SECURITY_PASSWORD_SINGLE_HASH": False,
        },
    )
    response = authenticate(app.test_client(), follow_redirects=True)
    assert b"Home Page" in response.data

    # Above created all accounts using bcrypt - now change over to argon
    # and verify that verify_and_update_password works
    app.config["SECURITY_PASSWORD_HASH"] = "argon2"
    app.config["SECURITY_PASSWORD_HASH_PASSLIB_OPTIONS"] = dict(argon2__rounds=1)
    app.config["SECURITY_PASSWORD_SCHEMES"] = ["argon2", "bcrypt"]
    app.security.pwd_context = _get_pwd_context(app)
    app.security.hashing_context = _get_hashing_context(app)
    with app.app_context():
        user1 = sqlalchemy_datastore.find_user(email="gal@lp.com")
        assert app.security.pwd_context.identify(user1.password) == "bcrypt"
        assert verify_and_update_password("password", user1)
        # above should have rewritten password to argon1
        sqlalchemy_datastore.commit()
        assert verify_and_update_password("password", user1)
        user1 = sqlalchemy_datastore.find_user(email="gal@lp.com")
        assert app.security.pwd_context.identify(user1.password) == "argon2"


def test_missing_hash_salt_option(app, sqlalchemy_datastore):
    with raises(RuntimeError):
        init_app_with_options(
            app,
            sqlalchemy_datastore,
            **{
                "SECURITY_PASSWORD_HASH": "argon2",
                "SECURITY_PASSWORD_SALT": None,
                "SECURITY_PASSWORD_SINGLE_HASH": False,
            },
        )


def test_verify_password_argon2_opts(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "argon2",
            "SECURITY_PASSWORD_HASH_PASSLIB_OPTIONS": {
                "argon2__rounds": 1,
                "argon2__salt_size": 16,
                "argon2__hash_len": 16,
            },
        },
    )
    with app.app_context():
        hashed_pwd = hash_password("pass")
        assert "t=1" in hashed_pwd
        assert verify_password("pass", hashed_pwd)


@pytest.mark.skip
def test_bcrypt_speed(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "bcrypt",
            "SECURITY_PASSWORD_SALT": "salty",
            "SECURITY_PASSWORD_SINGLE_HASH": False,
        },
    )
    with app.app_context():
        print(timeit.timeit(lambda: hash_password("pass"), number=100))


@pytest.mark.skip
def test_argon2_speed(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "argon2",
            "SECURITY_PASSWORD_HASH_PASSLIB_OPTIONS": {"argon2__rounds": 10},
        },
    )
    with app.app_context():
        print(
            "Hash time for {} iterations: {}".format(
                100, timeit.timeit(lambda: hash_password("pass"), number=100)
            )
        )
