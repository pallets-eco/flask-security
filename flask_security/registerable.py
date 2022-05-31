"""
    flask_security.registerable
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security registerable module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2022 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app as app

from .confirmable import generate_confirmation_link
from .proxies import _security, _datastore
from .signals import user_registered
from .utils import config_value as cv, do_flash, get_message, hash_password, send_mail


def register_user(registration_form):
    """
    Calls datastore to create user, triggers post-registration logic
    (e.g. sending confirmation link, sending registration mail)
    :param registration_form: form with user registration data
    :return: user instance
    """

    user_model_kwargs = registration_form.to_dict(only_user=True)

    # passwords are always required - with UNIFIED_SIGNIN
    if user_model_kwargs["password"]:
        user_model_kwargs["password"] = hash_password(user_model_kwargs["password"])
    user = _datastore.create_user(**user_model_kwargs)

    # if they didn't give a password - auto-setup email magic links (if UNIFIED SIGNIN)
    if not user_model_kwargs["password"] and cv("UNIFIED_SIGNIN"):
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

    if cv("SEND_REGISTER_EMAIL"):
        send_mail(
            cv("EMAIL_SUBJECT_REGISTER"),
            user.email,
            "welcome",
            user=user,
            confirmation_link=confirmation_link,
            confirmation_token=token,
        )

    return user
