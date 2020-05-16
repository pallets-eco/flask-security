"""
    test_hashing
    ~~~~~~~~~~~~

    hashing tests
"""

import timeit

import pytest
from pytest import raises
from tests.test_utils import authenticate, init_app_with_options
from passlib.hash import argon2, pbkdf2_sha256, django_pbkdf2_sha256, plaintext

from flask_security.utils import hash_password, verify_password, get_hmac


def test_verify_password_bcrypt_double_hash(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "bcrypt",
            "SECURITY_PASSWORD_SALT": "salty",
            "SECURITY_PASSWORD_SINGLE_HASH": False,
        }
    )
    with app.app_context():
        assert verify_password("pass", hash_password("pass"))


def test_verify_password_bcrypt_single_hash(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "bcrypt",
            "SECURITY_PASSWORD_SALT": None,
            "SECURITY_PASSWORD_SINGLE_HASH": True,
        }
    )
    with app.app_context():
        assert verify_password("pass", hash_password("pass"))


def test_verify_password_single_hash_list(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "bcrypt",
            "SECURITY_PASSWORD_SALT": "salty",
            "SECURITY_PASSWORD_SINGLE_HASH": ["django_pbkdf2_sha256", "plaintext"],
            "SECURITY_PASSWORD_SCHEMES": [
                "bcrypt",
                "pbkdf2_sha256",
                "django_pbkdf2_sha256",
                "plaintext",
            ],
        }
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
            "SECURITY_PASSWORD_HASH": "bcrypt",
            "SECURITY_PASSWORD_SINGLE_HASH": False,
            "SECURITY_PASSWORD_SCHEMES": ["bcrypt", "plaintext"],
        }
    )
    with app.app_context():
        # double hash
        assert verify_password("pass", hash_password("pass"))
        # single hash
        assert verify_password("pass", plaintext.hash("pass"))


def test_verify_password_bcrypt_rounds_too_low(app, sqlalchemy_datastore):
    with raises(ValueError) as exc_msg:
        init_app_with_options(
            app,
            sqlalchemy_datastore,
            **{
                "SECURITY_PASSWORD_HASH": "bcrypt",
                "SECURITY_PASSWORD_SALT": "salty",
                "SECURITY_PASSWORD_HASH_OPTIONS": {"bcrypt": {"rounds": 3}},
            }
        )
    assert all(s in str(exc_msg.value) for s in ["rounds", "too low"])


def test_login_with_bcrypt_enabled(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "bcrypt",
            "SECURITY_PASSWORD_SALT": "salty",
            "SECURITY_PASSWORD_SINGLE_HASH": False,
        }
    )
    response = authenticate(app.test_client(), follow_redirects=True)
    assert b"Home Page" in response.data


def test_missing_hash_salt_option(app, sqlalchemy_datastore):
    with raises(RuntimeError):
        init_app_with_options(
            app,
            sqlalchemy_datastore,
            **{
                "SECURITY_PASSWORD_HASH": "bcrypt",
                "SECURITY_PASSWORD_SALT": None,
                "SECURITY_PASSWORD_SINGLE_HASH": False,
            }
        )


def test_verify_password_argon2(app, sqlalchemy_datastore):
    init_app_with_options(
        app, sqlalchemy_datastore, **{"SECURITY_PASSWORD_HASH": "argon2"}
    )
    with app.app_context():
        hashed_pwd = hash_password("pass")
        assert verify_password("pass", hashed_pwd)
        assert "t=10" in hashed_pwd

        # Verify double hash
        assert verify_password("pass", argon2.hash(get_hmac("pass")))


def test_verify_password_argon2_opts(app, sqlalchemy_datastore):
    init_app_with_options(
        app,
        sqlalchemy_datastore,
        **{
            "SECURITY_PASSWORD_HASH": "argon2",
            "SECURITY_PASSWORD_HASH_PASSLIB_OPTIONS": {
                "argon2__rounds": 4,
                "argon2__salt_size": 16,
                "argon2__hash_len": 16,
            },
        }
    )
    with app.app_context():
        hashed_pwd = hash_password("pass")
        assert "t=4" in hashed_pwd
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
        }
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
        }
    )
    with app.app_context():
        print(
            "Hash time for {} iterations: {}".format(
                100, timeit.timeit(lambda: hash_password("pass"), number=100)
            )
        )
