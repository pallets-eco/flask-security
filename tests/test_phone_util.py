"""
test_phone_util
~~~~~~~~~~~~~~~

Tests for PhoneUtil class in flask_security.phone_util.
Covers phone number validation and canonicalization logic.
"""

import pytest
from flask_security.phone_util import PhoneUtil


# Use default app fixture from conftest.py
# Override config using the recommended settings marker
@pytest.mark.settings(phone_region_default="US")
@pytest.mark.parametrize(
    "input_number", ["123456", "bad-number-%%%", "+999", "abcdefgh"]
)
def test_invalid_phone_numbers_return_none(app, input_number):
    with app.app_context():
        phone_util = PhoneUtil(app)
        assert phone_util.get_canonical_form(input_number) is None
