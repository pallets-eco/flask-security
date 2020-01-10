# -*- coding: utf-8 -*-
"""
    flask_security.registerable
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security registerable module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app as app
from werkzeug.local import LocalProxy

from .confirmable import generate_confirmation_link
from .signals import user_registered
from .utils import config_value, do_flash, get_message, hash_password

# Convenient references
_security = LocalProxy(lambda: app.extensions["security"])

_datastore = LocalProxy(lambda: _security.datastore)


def register_user(registration_form):
    """
    Calls datastore to create user, triggers post-registration logic
    (e.g. sending confirmation link, sending registration mail)
    :param registration_form: form with user registration data
    :return: user instance
    """

    user_model_kwargs = registration_form.to_dict(only_user=True)

    confirmation_link, token = None, None
    user_model_kwargs["password"] = hash_password(user_model_kwargs["password"])
    user = _datastore.create_user(**user_model_kwargs)
    _datastore.commit()

    if _security.confirmable:
        confirmation_link, token = generate_confirmation_link(user)
        do_flash(*get_message("CONFIRM_REGISTRATION", email=user.email))

    user_registered.send(app._get_current_object(), user=user, confirm_token=token)

    if config_value("SEND_REGISTER_EMAIL"):
        _security._send_mail(
            config_value("EMAIL_SUBJECT_REGISTER"),
            user.email,
            "welcome",
            user=user,
            confirmation_link=confirmation_link,
        )

    return user
