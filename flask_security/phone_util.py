# -*- coding: utf-8 -*-
"""
    flask_security.phone_util
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Utility class for managing phone numbers

    :copyright: (c) 2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    Avoid making 'phonenumbers' a required package unless needed.
"""

from .utils import config_value, get_message


class PhoneUtil(object):
    """
    Provide parsing and validation for user inputted phone numbers.
    Subclass this to use a different underlying phone number parsing library.

    To provide your own implementation, pass in the class as ``phone_util_cls``
    at init time. Your class will be instantiated once prior to the first
    request being handled.

    .. versionadded:: 3.4.0
    """

    def validate_phone_number(self, input_data):
        """ Return ``None`` if a valid phone number else an error message. """
        import phonenumbers

        try:
            z = phonenumbers.parse(
                input_data, region=config_value("PHONE_REGION_DEFAULT")
            )
            if phonenumbers.is_valid_number(z):
                return None
        except phonenumbers.phonenumberutil.NumberParseException:
            pass
        return get_message("PHONE_INVALID")[0]

    def get_canonical_form(self, input_data):
        """ Validate and return a canonical form to be stored in DB
        and compared against.
        Returns ``None`` if input isn't a valid phone number.
        """
        import phonenumbers

        try:
            z = phonenumbers.parse(
                input_data, region=config_value("PHONE_REGION_DEFAULT")
            )
            if phonenumbers.is_valid_number(z):
                return phonenumbers.format_number(
                    z, phonenumbers.PhoneNumberFormat.E164
                )
            return None
        except phonenumbers.phonenumberutil.NumberParseException:
            return None
