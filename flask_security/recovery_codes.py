"""
    flask_security.recovery_codes
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security Recovery Codes Module

    :copyright: (c) 2022-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from __future__ import annotations

import typing as t

from flask import after_this_request, request, redirect
from flask_login import current_user


from .decorators import anonymous_user_required, auth_required, unauth_csrf
from .forms import (
    build_form_from_request,
    get_form_field_label,
    get_form_field_xlate,
    Form,
    Required,
    StringField,
    SubmitField,
)
from .proxies import _datastore, _security
from .tf_plugin import tf_check_state, tf_illegal_state
from .utils import (
    _,
    base_render_json,
    config_value as cv,
    get_message,
    get_post_login_redirect,
    view_commit,
)

if t.TYPE_CHECKING:  # pragma: no cover
    from cryptography.fernet import MultiFernet
    import flask
    from flask.typing import ResponseValue
    from .datastore import User


class MfRecoveryCodesUtil:
    """Handle creation, checking, encrypting and decrypting recovery codes.
    Since these are rarely used - keep them encrypted until needed - yes
    if someone gets access to memory they can find the key...
    """

    def __init__(self, app: flask.Flask):
        self.cryptor: MultiFernet | None = None
        keys = cv("MULTI_FACTOR_RECOVERY_CODES_KEYS", app)
        # N.B. order is important - first key is 'primary'.
        if keys:
            self.setup_cryptor(keys)

    def setup_cryptor(self, keys: list[bytes]) -> None:
        from cryptography.fernet import Fernet, MultiFernet

        cryptors: list[Fernet] = []
        for key in keys:
            cryptors.append(Fernet(key))
        self.cryptor = MultiFernet(cryptors)

    def create_recovery_codes(self, user: User) -> list[str]:
        # Create new recovery codes and store in user record.
        # If configured codes are stored encrypted - but plainttext
        # versions are returned.
        new_codes = _security._totp_factory.generate_recovery_codes(
            cv("MULTI_FACTOR_RECOVERY_CODES_N")
        )
        _datastore.mf_set_recovery_codes(user, self.encrypt_codes(new_codes))
        return new_codes

    def get_recovery_codes(self, user: User) -> list[str]:
        ecodes = _datastore.mf_get_recovery_codes(user)
        return self.decrypt_codes(ecodes)

    def check_recovery_code(self, user: User, code: str) -> bool:
        # Verify code is valid
        codes = _datastore.mf_get_recovery_codes(user)
        dcodes = self.decrypt_codes(codes)
        return code in dcodes

    def delete_recovery_code(self, user: User, code: str) -> bool:
        # codes are single use - so delete after use.
        # encrypting code gives different answer due to time stamp.
        # we don't want to re-encrypt other codes.
        codes = _datastore.mf_get_recovery_codes(user)
        if self.cryptor:
            codes = self.decrypt_codes(codes)
        idx = codes.index(code)
        return _datastore.mf_delete_recovery_code(user, idx)

    def encrypt_codes(self, codes: list[str]) -> list[str]:
        if not self.cryptor:
            return codes
        ecodes = []
        for code in codes:
            ecodes.append(self.cryptor.encrypt(code.encode()).decode())
        return ecodes

    def decrypt_codes(self, codes: list[str]) -> list[str]:
        from cryptography.fernet import InvalidToken

        if not self.cryptor:
            return codes
        dcodes = []
        for code in codes:
            try:
                dcode = self.cryptor.decrypt(
                    code.encode(), cv("MULTI_FACTOR_RECOVERY_CODE_TTL")
                )
                dcodes.append(dcode.decode())
            except InvalidToken:
                # should we delete this?
                pass
        return dcodes


class MfRecoveryCodesForm(Form):
    """Generate and fetch recovery codes"""

    # show_codes is a GET option., generate_new_codes is a POST option
    show_codes = SubmitField(get_form_field_xlate(_("Show Recovery Codes")))
    generate_new_codes = SubmitField(
        get_form_field_xlate(_("Generate New Recovery Codes"))
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):  # pragma: no cover
            return False
        return True


class MfRecoveryForm(Form):
    """Accept recovery code for second factor authentication"""

    code = StringField(
        get_form_field_xlate(_("Recovery Code")),
        validators=[Required()],
    )
    submit = SubmitField(get_form_field_label("submitcode"))

    def __init__(self, *args: t.Any, **kwargs: t.Any):
        super().__init__(*args, **kwargs)
        # filled by view
        self.user: User | None = None

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):  # pragma: no cover
            return False
        assert self.user is not None
        if not _security._mf_recovery_codes_util.check_recovery_code(
            self.user, self.code.data
        ):
            self.code.errors.append(get_message("INVALID_RECOVERY_CODE")[0])
            return False
        return True


@auth_required(
    lambda: cv("API_ENABLED_METHODS"),
    within=lambda: cv("FRESHNESS"),
    grace=lambda: cv("FRESHNESS_GRACE_PERIOD"),
)
def mf_recovery_codes() -> ResponseValue:
    """
    Create and download multi-factor recovery codes.
    For forms, we want the user to explicitly request to see the codes - so
    the form has a show_codes submit button.
    """
    form = t.cast(
        MfRecoveryCodesForm, build_form_from_request("mf_recovery_codes_form")
    )

    if form.validate_on_submit():
        # generate new codes
        codes = _security._mf_recovery_codes_util.create_recovery_codes(current_user)
        after_this_request(view_commit)
        if _security._want_json(request):
            payload = dict(recovery_codes=codes)
            return base_render_json(form, include_user=False, additional=payload)
        return _security.render_template(
            cv("MULTI_FACTOR_RECOVERY_CODES_TEMPLATE"),
            mf_recovery_codes_form=form,
            recovery_codes=codes,
            **_security._run_ctx_processor("mf_recovery_codes"),
        )

    codes = _security._mf_recovery_codes_util.get_recovery_codes(current_user)
    if _security._want_json(request):
        return base_render_json(
            form, include_user=False, additional=dict(recovery_codes=codes)
        )
    show_codes = request.args.get("show_codes", False)
    if show_codes and not codes:
        form.show_codes.errors = []
        form.show_codes.errors.append(get_message("NO_RECOVERY_CODES_SETUP")[0])
    return _security.render_template(
        cv("MULTI_FACTOR_RECOVERY_CODES_TEMPLATE"),
        mf_recovery_codes_form=form,
        recovery_codes=codes if show_codes else [],
        **_security._run_ctx_processor("mf_recovery_codes"),
    )


@anonymous_user_required
@unauth_csrf()
def mf_recovery():
    """View for entering a recovery code.

    User must have already provided valid username/password.
    User must have already established 2FA

    """
    form = t.cast(MfRecoveryForm, build_form_from_request("mf_recovery_form"))
    form.user = tf_check_state(["ready"])
    if not form.user:
        return tf_illegal_state(form, cv("TWO_FACTOR_ERROR_VIEW"))

    if form.validate_on_submit():
        # Valid code - we want these to be one time - so remove it from list
        _security._mf_recovery_codes_util.delete_recovery_code(
            form.user, form.code.data
        )
        after_this_request(view_commit)

        # In the recovery case - don't set/offer validity token.
        _security.two_factor_plugins.tf_complete(form.user, True)

        if not _security._want_json(request):
            return redirect(get_post_login_redirect())
        else:
            return base_render_json(form)

    if _security._want_json(request):
        return base_render_json(form, include_user=False)
    return _security.render_template(
        cv("MULTI_FACTOR_RECOVERY_TEMPLATE"),
        mf_recovery_form=form,
        **_security._run_ctx_processor("mf_recovery"),
    )
