"""
    flask_security.change_email
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security Change Email module

    :copyright: (c) 2024-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    Allow user to change their email address.
    If CHANGE_EMAIL_CONFIRM is set then the user will receive an email
    at the new email address with a token that can be used to verify and change
    emails. Upon success - if CHANGE_EMAIL_NOTIFY_OLD is set, an email will be sent
    to the old email address.
"""

from __future__ import annotations

import typing as t

from flask import after_this_request, request
from flask import current_app
from flask_login import current_user
from wtforms import SubmitField

from .decorators import auth_required
from .forms import (
    Form,
    UniqueEmailFormMixin,
    build_form_from_request,
    form_errors_munge,
    get_form_field_label,
)
from .proxies import _security, _datastore
from .quart_compat import get_quart_status
from .signals import change_email_instructions_sent, change_email_confirmed
from .utils import (
    base_render_json,
    check_and_get_token_status,
    config_value as cv,
    do_flash,
    get_message,
    get_url,
    get_within_delta,
    hash_data,
    send_mail,
    url_for_security,
    verify_hash,
    view_commit,
)

if t.TYPE_CHECKING:  # pragma: no cover
    from flask.typing import ResponseValue

if get_quart_status():  # pragma: no cover
    from quart import redirect
else:
    from flask import redirect


class ChangeEmailForm(Form, UniqueEmailFormMixin):
    submit = SubmitField(label=get_form_field_label("submit"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.existing_email_user = None


@auth_required(
    lambda: cv("API_ENABLED_METHODS"),
    within=lambda: cv("FRESHNESS"),
    grace=lambda: cv("FRESHNESS_GRACE_PERIOD"),
)
def change_email() -> ResponseValue:
    """Start Change Email for an existing authenticated user"""
    payload: dict[str, t.Any]

    form: ChangeEmailForm = t.cast(
        ChangeEmailForm, build_form_from_request("change_email_form")
    )

    if form.validate_on_submit():
        _send_instructions(current_user, form.email.data)
        if not _security._want_json(request):
            do_flash(*get_message("CHANGE_EMAIL_SENT", email=form.email.data))
        # Drop through..

    # All paths get here
    if (
        request.method == "POST"
        and cv("RETURN_GENERIC_RESPONSES")
        and form.existing_email_user
    ):
        # Don't let an existing user enumerate registered emails
        fields_to_squash: dict[str, dict[str, str]] = dict(email=dict())
        form_errors_munge(form, fields_to_squash)
        if not form.errors:
            # only error is existing email - make it appear the same as if it worked
            # except that we don't send anything - while we could inform the email
            # that someone is trying to take it over - that could allow a user to
            # annoy another user.
            if not _security._want_json(request):
                do_flash(*get_message("CHANGE_EMAIL_SENT", email=form.email.data))
            # TODO - should we have a signal so we can tell application what is
            # is going on (otherwise it is pretty much a black-hole).
            # drop through - will return a successful response.

    if _security._want_json(request):
        form.user = current_user
        payload = dict(current_email=current_user.email)
        return base_render_json(form, additional=payload)

    return _security.render_template(
        cv("CHANGE_EMAIL_TEMPLATE"),
        change_email_form=form,
        current_email=current_user.email,
        **_security._run_ctx_processor("change_email"),
    )


def change_email_confirm(token):
    """
    View function which handles a change email confirmation request.
    This is always a GET from an email - so for 'spa' must always redirect.
    """
    expired, invalid, user, new_email = _verify_token_status(token)

    if invalid or expired:
        if expired:
            m, c = get_message(
                "CHANGE_EMAIL_EXPIRED",
                within=cv("CHANGE_EMAIL_WITHIN"),
            )
        else:
            m, c = get_message("API_ERROR")
        if cv("REDIRECT_BEHAVIOR") == "spa":
            return redirect(get_url(cv("CHANGE_EMAIL_ERROR_VIEW"), qparams={c: m}))
        do_flash(m, c)
        return redirect(
            get_url(cv("CHANGE_EMAIL_ERROR_VIEW")) or url_for_security("change_email")
        )

    _update_user_email(user, new_email)
    after_this_request(view_commit)
    m, c = get_message("CHANGE_EMAIL_CONFIRMED")
    if cv("REDIRECT_BEHAVIOR") == "spa":
        return redirect(
            get_url(
                cv("POST_CHANGE_EMAIL_VIEW"),
                qparams=user.get_redirect_qparams({c: m}),
            )
        )
    do_flash(m, c)
    return redirect(
        get_url(cv("POST_CHANGE_EMAIL_VIEW")) or get_url(cv("POST_LOGIN_VIEW"))
    )


def _generate_token(user, new_email):
    """Generates a unique confirmation token for the specified user.

    :param user: The user to work with
    :param new_email: The requested email
    """
    data = [str(user.fs_uniquifier), hash_data(user.email), new_email]
    return _security.change_email_serializer.dumps(data)


def _generate_link(user, new_email):
    token = _generate_token(user, new_email)
    return url_for_security("change_email_confirm", token=token, _external=True), token


def _send_instructions(user, new_email):
    """Sends the change email instructions email for the specified user.

    :param user: The user to send the instructions to
    :param new_email: The requested new email
    """

    link, token = _generate_link(user, new_email)

    send_mail(
        cv("CHANGE_EMAIL_SUBJECT"),
        new_email,
        "change_email_instructions",
        user=user,
        link=link,
        token=token,
    )

    change_email_instructions_sent.send(
        current_app._get_current_object(),
        _async_wrapper=current_app.ensure_sync,
        user=user,
        new_email=new_email,
        token=token,
    )


def _verify_token_status(token):
    """Verify token and contents.
    In general, we return pretty generic results - including checking the requested
    new_email is still available (and if not return 'invalid').
    """
    expired, invalid, state = check_and_get_token_status(
        token, "change_email", get_within_delta("CHANGE_EMAIL_WITHIN")
    )
    if invalid or expired:
        return expired, invalid, None, None
    fid, hashed_email, new_email = state
    user = _datastore.find_user(fs_uniquifier=fid)
    if not user or not verify_hash(hashed_email, user.email):
        return False, True, None, None

    # verify that new_email is still available
    if _datastore.find_user(email=new_email):
        return False, True, user, None
    return expired, invalid, user, new_email


def _update_user_email(user, new_email):
    old_email = user.email
    user.email = new_email
    user.confirmed_at = _security.datetime_factory()
    _datastore.put(user)
    change_email_confirmed.send(
        current_app._get_current_object(),
        _async_wrapper=current_app.ensure_sync,
        user=user,
        old_email=old_email,
    )
