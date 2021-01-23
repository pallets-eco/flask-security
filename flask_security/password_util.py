"""
    flask_security.password_util
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Utility class providing methods for validating and normalizing passwords.

    :copyright: (c) 2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

"""
import unicodedata

from .utils import (
    config_value,
    password_length_validator,
    password_breached_validator,
    password_complexity_validator,
)


class PasswordUtil:
    """
    Utility class providing methods for validating and normalizing passwords.

    To provide your own implementation, pass in the class as ``password_util_cls``
    at init time.  Your class will be instantiated once as part of app initialization.

    .. versionadded:: 4.0.0
    """

    def __init__(self, app):
        """Instantiate class.

        :param app: The Flask application being initialized.
        """
        pass

    def normalize(self, password):
        """
        Given an input password - return a normalized version (using Python's
        unicodedata.normalize()).
        Must be called in app context and uses
        :py:data:`SECURITY_PASSWORD_NORMALIZE_FORM` config variable.
        """
        cf = config_value("PASSWORD_NORMALIZE_FORM")
        if cf:
            return unicodedata.normalize(cf, password)
        return password

    def validate(self, password, is_register, **kwargs):
        """
        Password validation.
        Called in app/request context.

        If is_register is True then kwargs will be the contents of the register form.
        If is_register is False, then there is a single kwarg "user" which has the
        current user data model.

        The password is first normalized then validated.
        Return value is a tuple ([msgs], normalized_password)
        """

        cf = config_value("PASSWORD_NORMALIZE_FORM")
        if cf:
            pnorm = unicodedata.normalize(cf, password)
        else:
            pnorm = password

        notok = password_length_validator(pnorm)
        if notok:
            return notok, pnorm

        notok = password_breached_validator(pnorm)
        if notok:
            return notok, pnorm

        return password_complexity_validator(pnorm, is_register, **kwargs), pnorm
