"""
test_phone_util
~~~~~~~~~~~~~~~

Tests for PhoneUtil class in flask_security.phone_util.
Covers phone number validation and canonicalization logic.
"""

import pytest
from flask_security.phone_util import PhoneUtil
from flask import Flask


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["SECURITY_PHONE_REGION_DEFAULT"] = "US"
    return app


def test_get_canonical_form_invalid_number(app):
    with app.app_context():
        phone_util = PhoneUtil(app)
        result = phone_util.get_canonical_form("123456")
        assert result is None


def test_get_canonical_form_malformed_number(app):
    with app.app_context():
        phone_util = PhoneUtil(app)
        result = phone_util.get_canonical_form("bad-number-%%%")
        assert result is None
