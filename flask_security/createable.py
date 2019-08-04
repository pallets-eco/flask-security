# -*- coding: utf-8 -*-
"""
    flask_security.createable
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security createable module

    :copyright: (c) 2012 by Matt Wright.
    :author: Azu Nwaokobia
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app as app
from werkzeug.local import LocalProxy

from .recoverable import generate_reset_password_token
from .signals import user_created
from .utils import config_value, generate_default_password, url_for_security

# Convenient references
_security = LocalProxy(lambda: app.extensions["security"])

_datastore = LocalProxy(lambda: _security.datastore)


def create_user(**kwargs):
    kwargs["password"] = generate_default_password()
    user = _datastore.create_user(**kwargs)
    _datastore.commit()

    token = generate_reset_password_token(user)
    reset_link = url_for_security("reset_password", token=token, _external=True)
    user_created.send(app._get_current_object(), user=user, token=token)
    _security.send_mail(
        config_value("EMAIL_SUBJECT_USER_CREATED"),
        user.email,
        "create_user",
        user=user,
        reset_link=reset_link,
    )
