"""
flask_security.tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Flask-Security Tokens module

:copyright: (c) 2026-2026 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.

This module implements refresh and authentication tokens.

- each time a refresh token is used, a new one on the same 'family' is created (by
  incrementing the 'gen' field)

TODO
 - add ability for app to add/verify additional stuff in refresh_token
 - allow logout to have refresh token and revoke it
 - add support for HTTP-only cookie (watch for CSRF issue)
 - change TOKEN_MAX_AGE to accept timedelta and change default to 30minutes or so.
 - implment rotation overlap period:
   https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-rotation

"""

from __future__ import annotations

from enum import Enum, auto
import typing as t

from flask import abort, request, after_this_request, current_app
from itsdangerous import BadSignature
from wtforms import StringField

from .forms import (
    Form,
    RequiredLocalize,
    SubmitField,
    get_form_field_label,
    get_form_field_xlate,
    build_form_from_request,
)
from .proxies import _security, _datastore
from .signals import refresh_tracker_revoked, refresh_tracker_created
from .utils import config_value as cv, _, view_commit, get_message, base_render_json

if t.TYPE_CHECKING:  # pragma: no cover
    from flask.typing import ResponseValue
    from .core import UserMixin, RefreshTrackerMixin


class RefreshTokenErrors(Enum):
    INVALID = auto()
    EXPIRED = auto()
    NOT_FOUND = auto()
    GEN_MISMATCH = auto()
    REVOKED = auto()


def response_tokens(user: UserMixin, payload: dict[str, t.Any]) -> None:
    """Views that authenticate and return JSON can also provide an auth token
    In addition, with the new refresh token feature, they should return a refresh token
    """
    try:
        token = user.get_auth_token()
    except ValueError:
        # application has fs_token_uniquifier attribute but it
        # hasn't been initialized. Since we are in a request context
        # we can do that here.
        _datastore.set_token_uniquifier(user)
        after_this_request(view_commit)
        token = user.get_auth_token()
    payload["user"]["authentication_token"] = token

    if _security.refresh_token:
        after_this_request(view_commit)
        refresh_tracker, refresh_token = new_refresh_tracker(user, name="default")
        payload["user"]["refresh_token"] = refresh_token


def new_refresh_tracker(user: UserMixin, name: str) -> tuple[RefreshTrackerMixin, str]:
    """This creates a new refresh tracker and uses that
     to create a new refresh token

    Caller must commit to the datastore.
    """

    # Take this opportunity to cleanup old refresh trackers
    _datastore.cleanup_refresh_trackers(
        user,
        expired=cv("REFRESH_TOKEN_CLEANUP_EXPIRED"),
        revoked=cv("REFRESH_TOKEN_CLEANUP_REVOKED"),
    )

    expires_at = _security.datetime_factory() + cv("REFRESH_TOKEN_MAX_AGE")
    refresh_tracker = _datastore.create_refresh_tracker(
        user, name=name, expires_at=expires_at
    )

    tdata: dict[str, t.Any] = {
        "ver": str(1),
        "uid": getattr(user, _datastore.get_token_uniquifier_name()),
        "expires_at": refresh_tracker.expires_at.timestamp(),
        "last_used_at": refresh_tracker.last_used_at.timestamp(),
        "name": name,
        "family": refresh_tracker.refresh_family,
        "gen": refresh_tracker.gen,
    }
    # Let application add things
    # user.augment_refresh_token(tdata)

    refresh_tracker_created.send(
        current_app._get_current_object(),  # type: ignore
        _async_wrapper=current_app.ensure_sync,
        user=user,
        refresh_tracker=refresh_tracker,
    )
    return refresh_tracker, _security.refresh_token_serializer.dumps(tdata)


def get_refresh_token(refresh_tracker: RefreshTrackerMixin, user: UserMixin) -> str:
    """This creates a new refresh token from an existing refresh tracker"""
    tdata: dict[str, t.Any] = {
        "ver": str(1),
        "uid": getattr(user, _datastore.get_token_uniquifier_name()),
        "expires_at": refresh_tracker.expires_at.timestamp(),
        "name": refresh_tracker.name,
        "family": refresh_tracker.refresh_family,
        "gen": refresh_tracker.gen,
    }
    # Let application add things
    # self.augment_refresh_token(tdata)
    return _security.refresh_token_serializer.dumps(tdata)


def verify_refresh_token(
    token: str,
) -> tuple[RefreshTrackerMixin | None, RefreshTokenErrors | None, str | None]:
    """Verifies the refresh token and returns the refresh tracker
    Note that we always return the UID if the token is properly signed.
    This lets the calling code possibly find the user and be able to inform
    the application via signals"""
    try:
        tdata = _security.refresh_token_serializer.loads(token)
    except (BadSignature, TypeError, ValueError):
        return None, RefreshTokenErrors.INVALID, None

    if not (refresh_tracker := _datastore.find_refresh_tracker(tdata["family"])):
        return None, RefreshTokenErrors.NOT_FOUND, None
    if refresh_tracker.gen != tdata["gen"]:
        # this is considered an attack (or bad code)
        return refresh_tracker, RefreshTokenErrors.GEN_MISMATCH, tdata["uid"]
    if refresh_tracker.expires_at < _security.datetime_factory():
        return refresh_tracker, RefreshTokenErrors.EXPIRED, tdata["uid"]
    if (_security.datetime_factory() - refresh_tracker.last_used_at) > cv(
        "REFRESH_TOKEN_MAX_IDLE"
    ):
        return refresh_tracker, RefreshTokenErrors.EXPIRED, tdata["uid"]
    if refresh_tracker.revoked_at and (
        refresh_tracker.revoked_at < _security.datetime_factory()
    ):
        return refresh_tracker, RefreshTokenErrors.REVOKED, tdata["uid"]

    return refresh_tracker, None, tdata["uid"]


class RefreshTokenForm(Form):
    refresh_token = StringField(
        get_form_field_xlate(_("Refresh Token")),
        validators=[RequiredLocalize()],
    )
    submit = SubmitField(label=get_form_field_label("submit"))

    # returned to caller
    refresh_errors: RefreshTokenErrors | None = None
    refresh_tracker: RefreshTrackerMixin | None = None
    user: UserMixin | None = None

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):  # pragma: no cover
            return False

        assert self.refresh_token.data is not None  # validator RequiredLocalize
        assert isinstance(self.refresh_token.errors, list)

        self.refresh_tracker, self.refresh_errors, uid = verify_refresh_token(
            self.refresh_token.data
        )

        # Try to find user even if there are errors to aid logging
        if uid:
            self.user = _security.datastore.find_user(
                case_insensitive=False, **{_datastore.get_token_uniquifier_name(): uid}
            )
        if self.refresh_errors:
            self.refresh_token.errors.append(
                get_message("REFRESH_TOKEN_INVALID", reason=self.refresh_errors.name)[0]
            )
            return False
        if not self.user:
            self.refresh_token.errors.append(get_message("USER_DOES_NOT_EXIST")[0])
            return False
        return True


def refresh() -> ResponseValue:
    if not request.is_json:
        abort(400)

    form: RefreshTokenForm = t.cast(
        RefreshTokenForm, build_form_from_request("refresh_token_form")
    )

    if form.validate_on_submit():
        assert form.user
        assert form.refresh_tracker
        after_this_request(view_commit)
        _datastore.exchange_refresh_tracker(form.refresh_tracker)
        payload = dict()
        payload["user"] = form.user.get_security_payload()
        payload["user"]["authentication_token"] = form.user.get_auth_token()
        payload["user"]["refresh_token"] = get_refresh_token(
            form.refresh_tracker, form.user
        )
        return _security._render_json(payload, 200, None, form.user)

    # Failed validation - if it was a GEN_MISMATCH this could be a hack and we should
    # invalidate/revoke the entire token family.
    if form.refresh_errors == RefreshTokenErrors.GEN_MISMATCH:
        assert form.refresh_tracker
        after_this_request(view_commit)
        _datastore.revoke_refresh_tracker(form.refresh_tracker)
        refresh_tracker_revoked.send(
            current_app._get_current_object(),  # type: ignore
            _async_wrapper=current_app.ensure_sync,
            user=form.user,
            refresh_tracker=form.refresh_tracker,
            refresh_errors=form.refresh_errors,
        )
    return base_render_json(form, include_user=False)
