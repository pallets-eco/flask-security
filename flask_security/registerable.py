"""
    flask_security.registerable
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security registerable module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2021 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import uuid

from flask import current_app as app

from .confirmable import generate_confirmation_link
from .proxies import _security, _datastore
from .signals import user_registered
from .utils import config_value, do_flash, get_message, hash_password, send_mail


def register_user(registration_form):
    """
    Calls datastore to create user, triggers post-registration logic
    (e.g. sending confirmation link, sending registration mail)
    :param registration_form: form with user registration data
    :return: user instance
    """

    user_model_kwargs = registration_form.to_dict(only_user=True)
    blank_password = not user_model_kwargs["password"]

    if blank_password:
        # For no password - set an unguessable password.
        # Since we still allow 'plaintext' as a password scheme - can't use a simple
        # sentinel.
        user_model_kwargs["password"] = "NoPassword-" + uuid.uuid4().hex

    user_model_kwargs["password"] = hash_password(user_model_kwargs["password"])
    user = _datastore.create_user(**user_model_kwargs)

    # if they didn't give a password - auto-setup email magic links.
    if blank_password:
        _datastore.us_setup_email(user)

    confirmation_link, token = None, None
    if _security.confirmable:
        confirmation_link, token = generate_confirmation_link(user)
        do_flash(*get_message("CONFIRM_REGISTRATION", email=user.email))

    user_registered.send(
        app._get_current_object(),
        user=user,
        confirm_token=token,
        confirmation_token=token,
        form_data=registration_form.to_dict(only_user=False),
    )

    if config_value("SEND_REGISTER_EMAIL"):
        send_mail(
            config_value("EMAIL_SUBJECT_REGISTER"),
            user.email,
            "welcome",
            user=user,
            confirmation_link=confirmation_link,
            confirmation_token=token,
        )

    return user
