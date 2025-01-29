"""
flask_security.change_username
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Flask-Security Change Username module

:copyright: (c) 2025-2025 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.

Allow user to change their username.
This is really just for when username is used as an authenticating
identity (and therefore has to be unique).

The basic feature allows an authenticated user to change their username
to any available username. Normalization and validation take place
using username_util.
This doesn't offer any defense against username enumeration by another user or
preventing a user from constantly changing their username. Applications
could use the UsernameUtil.check_username() method to implement this.

Think about: username is normally considered 'public' however as an identity
should we follow a change protocol more like email - require a confirmation from
the registered email.

"""

from __future__ import annotations

import typing as t

from flask import after_this_request, request
from flask import current_app
from flask_login import current_user
from wtforms import Field, SubmitField

from .decorators import auth_required
from .forms import (
    Form,
    build_form_from_request,
    get_form_field_label,
)
from .proxies import _security, _datastore
from .quart_compat import get_quart_status
from .signals import username_changed
from .utils import (
    base_render_json,
    config_value as cv,
    do_flash,
    get_message,
    get_url,
    send_mail,
    view_commit,
)

if t.TYPE_CHECKING:  # pragma: no cover
    from flask.typing import ResponseValue

if get_quart_status():  # pragma: no cover
    from quart import redirect
else:
    from flask import redirect


class ChangeUsernameForm(Form):
    """Change Username Form.
    There is a single element - 'username'
    that will be validated by calling :meth:`.UsernameUtil.validate`
    then verified to be unique in the DB.

    username field value injected at init_app time with build_username_field()
    """

    username: t.ClassVar[Field]
    submit = SubmitField(label=get_form_field_label("submit"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


@auth_required(
    lambda: cv("API_ENABLED_METHODS"),
    within=lambda: cv("FRESHNESS"),
    grace=lambda: cv("FRESHNESS_GRACE_PERIOD"),
)
def change_username() -> ResponseValue:
    """Start Change Username for an existing authenticated user"""
    payload: dict[str, t.Any]

    form: ChangeUsernameForm = t.cast(
        ChangeUsernameForm, build_form_from_request("change_username_form")
    )

    if form.validate_on_submit():
        # simple - just change username
        form.user = current_user
        after_this_request(view_commit)
        update_username(form.user, form.username.data)
        if _security._want_json(request):
            return base_render_json(form)

        do_flash(*get_message("USERNAME_CHANGE"))
        return redirect(
            get_url(cv("POST_CHANGE_USERNAME_VIEW")) or get_url(cv("POST_LOGIN_VIEW"))
        )

    if _security._want_json(request):
        form.user = current_user
        payload = dict(current_username=current_user.username)
        return base_render_json(form, additional=payload)

    return _security.render_template(
        cv("CHANGE_USERNAME_TEMPLATE"),
        change_username_form=form,
        current_username=current_user.username,
        **_security._run_ctx_processor("change_username"),
    )


def update_username(user, new_username):
    old_username = user.username
    user.username = new_username
    _datastore.put(user)
    _send_username_changed_notice(user)
    username_changed.send(
        current_app._get_current_object(),
        _async_wrapper=current_app.ensure_sync,
        user=user,
        old_username=old_username,
    )


def _send_username_changed_notice(user):
    """Sends the username changed notice email for the specified user.

    :param user: The user to send the notice to
    """
    if cv("SEND_USERNAME_CHANGE_EMAIL"):
        subject = cv("EMAIL_SUBJECT_USERNAME_CHANGE_NOTICE")
        send_mail(subject, user.email, "change_username_notice", user=user)
