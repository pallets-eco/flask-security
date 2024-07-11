"""
    flask_security.webauthn
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security WebAuthn module

    :copyright: (c) 2021-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    This implements support for webauthn/FIDO2 Level 2 using the py_webauthn package.

    Check out: https://golb.hplar.ch/2019/08/webauthn.html
    for some ideas on recovery and adding additional authenticators.

    For testing - you can see your YubiKey (or other) resident keys in chrome!
    chrome://settings/securityKeys

    Observation: if key isn't resident than Chrome for example won't let you use
    it if it isn't part of allowedCredentials - throw error: referencing:
    https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client

    TODO:
        - update/add examples to support webauthn
        - should we universally add endpoint urls to JSON responses?
        - Add a way to order registered credentials so we can return an ordered list
          in allowCredentials.
        - #sctn-usecase-new-device-registration - allow more than one "first" key
          and have them not necessarily be cross-platform.. add form option?

    Research:
        - should we store things like user verified in 'last use'...
        - By insisting on 2FA if user has registered a webauthn - things
          get interesting if they try to log in on a different device....
          How would they register a security key for a new device? They would need
          some OTHER 2FA? Force them to register a NEW webauthn key?

"""

from __future__ import annotations

import json
import time
import typing as t
from functools import partial

from flask import abort, after_this_request, request, session
from flask import current_app
from flask_login import current_user
from wtforms import BooleanField, HiddenField, RadioField, StringField, SubmitField
from .forms import NextFormMixin

try:
    import webauthn
    from webauthn.authentication.verify_authentication_response import (
        VerifiedAuthentication,
    )
    from webauthn.registration.verify_registration_response import VerifiedRegistration
    from webauthn.helpers import (
        parse_registration_credential_json,
        parse_authentication_credential_json,
    )
    from webauthn.helpers.exceptions import (
        InvalidAuthenticationResponse,
        InvalidJSONStructure,
        InvalidRegistrationResponse,
    )
    from webauthn.helpers.structs import (
        AuthenticatorTransport,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType,
        UserVerificationRequirement,
    )
    from webauthn.helpers import bytes_to_base64url
except ImportError:  # pragma: no cover
    pass

from .decorators import anonymous_user_required, auth_required, unauth_csrf
from .forms import (
    Form,
    Required,
    build_form_from_request,
    build_form,
    get_form_field_label,
    get_form_field_xlate,
)
from .proxies import _security, _datastore
from .quart_compat import get_quart_status
from .signals import wan_registered, wan_deleted
from .tf_plugin import TfPluginBase, tf_set_validity_token_cookie
from .utils import (
    _,
    base_render_json,
    check_and_get_token_status,
    config_value as cv,
    do_flash,
    get_message,
    get_post_login_redirect,
    get_post_verify_redirect,
    get_url,
    get_within_delta,
    login_user,
    lookup_identity,
    propagate_next,
    simple_render_json,
    url_for_security,
    view_commit,
)

if t.TYPE_CHECKING:  # pragma: no cover
    import flask
    from flask.typing import ResponseValue
    from flask_security import Security, UserMixin, WebAuthnMixin

if get_quart_status():  # pragma: no cover
    from quart import redirect
else:
    from flask import redirect


class WebAuthnRegisterForm(Form):
    name = StringField(
        get_form_field_xlate(_("Nickname")),
        validators=[Required(message="WEBAUTHN_NAME_REQUIRED")],
    )
    usage = RadioField(
        get_form_field_xlate(_("Usage")),
        choices=[
            ("first", get_form_field_xlate(_("Use as a first authentication factor"))),
            (
                "secondary",
                get_form_field_xlate(_("Use as a secondary authentication factor")),
            ),
        ],
        default="secondary",
        validate_choice=True,
    )
    submit = SubmitField(label=get_form_field_label("submit"), id="wan_register")

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False
        inuse = any([self.name.data == cred.name for cred in current_user.webauthn])
        if inuse:
            msg = get_message("WEBAUTHN_NAME_INUSE", name=self.name.data)[0]
            self.name.errors.append(msg)
            return False
        if not cv("WAN_ALLOW_AS_FIRST_FACTOR"):
            self.usage.data = "secondary"
        return True


class WebAuthnRegisterResponseForm(Form):
    credential = HiddenField()
    submit = SubmitField(label=get_form_field_label("submit"))

    # from state
    challenge: str
    name: str
    usage: str
    user_verification: bool
    # this is returned to caller (not part of the client form)
    registration_verification: VerifiedRegistration
    transports: list[AuthenticatorTransport] = []
    extensions: str

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False  # pragma: no cover
        inuse = any([self.name == cred.name for cred in current_user.webauthn])
        if inuse:
            msg = get_message("WEBAUTHN_NAME_INUSE", name=self.name)[0]
            self.credential.errors.append(msg)
            return False
        try:
            reg_cred = parse_registration_credential_json(self.credential.data)
        except (
            ValueError,
            KeyError,
            InvalidJSONStructure,
            InvalidRegistrationResponse,
        ):
            self.credential.errors.append(get_message("API_ERROR")[0])
            return False
        try:
            self.registration_verification = webauthn.verify_registration_response(
                credential=reg_cred,
                expected_challenge=self.challenge.encode(),
                expected_origin=_security._webauthn_util.origin(),
                expected_rp_id=request.host.split(":")[0],
                require_user_verification=self.user_verification,
            )
            if _datastore.find_webauthn(credential_id=reg_cred.raw_id):
                msg = get_message("WEBAUTHN_CREDENTIAL_ID_INUSE")[0]
                self.credential.errors.append(msg)
                return False
        except KeyError:
            self.credential.errors.append(get_message("API_ERROR")[0])
            return False
        except InvalidRegistrationResponse as exc:
            self.credential.errors.append(
                get_message("WEBAUTHN_NO_VERIFY", cause=str(exc))[0]
            )
            return False

        self.transports = (
            reg_cred.response.transports if reg_cred.response.transports else []
        )
        # Alas py_webauthn doesn't support extensions
        response_full = json.loads(self.credential.data)
        # TODO - verify this is JSON (created with JSON.stringify)
        self.extensions = response_full.get("extensions", None)
        return True


class WebAuthnSigninForm(Form, NextFormMixin):
    identity = StringField(get_form_field_label("identity"))
    remember = BooleanField(get_form_field_label("remember_me"))
    submit = SubmitField(label=get_form_field_xlate(_("Start")), id="wan_signin")

    user: UserMixin | None = None
    # set by caller - is this a second factor authentication?
    is_secondary: bool

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.remember.default = cv("DEFAULT_REMEMBER_ME")

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False  # pragma: no cover
        user = None
        if self.is_secondary:
            if "tf_user_id" in session:
                user = _datastore.find_user(fs_uniquifier=session["tf_user_id"])
        elif cv("WAN_ALLOW_USER_HINTS"):
            # If we allow HINTS - provide them - but don't error
            # out if an unknown or disabled account - that would provide too
            # much 'discovery' capability of un-authenticated users.
            if self.identity.data:
                user = lookup_identity(self.identity.data)
        if user and user.is_active:
            self.user = user
        return True


class WebAuthnSigninResponseForm(Form, NextFormMixin):
    """
    This form is used both for signin (primary/first or secondary) and verify.
    """

    remember = HiddenField()
    submit = SubmitField(label=get_form_field_label("submit"))
    credential = HiddenField()

    # set by caller
    challenge: str
    user_verification: bool
    is_secondary: bool
    is_verify: bool
    # returned to caller
    authentication_verification: VerifiedAuthentication
    user: UserMixin | None = None
    cred: WebAuthnMixin | None = None
    # Set to True if this authentication qualifies as 'multi-factor'
    mf_check: bool = False

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False  # pragma: no cover
        try:
            auth_cred = parse_authentication_credential_json(self.credential.data)
        except (
            ValueError,
            KeyError,
            InvalidJSONStructure,
            InvalidAuthenticationResponse,
        ):
            self.credential.errors.append(get_message("API_ERROR")[0])
            return False

        # Look up credential Id (raw_id) and user. 7.2.6/7
        self.cred = _datastore.find_webauthn(credential_id=auth_cred.raw_id)
        if not self.cred:
            self.credential.errors.append(
                get_message("WEBAUTHN_UNKNOWN_CREDENTIAL_ID")[0]
            )
            return False
        # This shouldn't be able to happen if datastore properly cascades
        # delete
        self.user = _datastore.find_user_from_webauthn(self.cred)
        if not self.user:  # pragma: no cover
            self.credential.errors.append(
                get_message("WEBAUTHN_ORPHAN_CREDENTIAL_ID")[0]
            )
            return False

        # Verify user Handle. 7.2.6
        if auth_cred.response.user_handle:
            if (
                auth_cred.response.user_handle
                != self.user.fs_webauthn_user_handle.encode()
            ):
                self.credential.errors.append(
                    get_message("WEBAUTHN_MISMATCH_USER_HANDLE")[0]
                )
                return False

        # Make sure the usage of credential matches configured
        if self.is_verify:
            usage = cv("WAN_ALLOW_AS_VERIFY")
        elif self.is_secondary:
            usage = "secondary"
        else:
            usage = "first"
        if not is_cred_usable(self.cred, usage):
            self.credential.errors.append(
                get_message("WEBAUTHN_CREDENTIAL_WRONG_USAGE")[0]
            )
            return False

        if not self.user.is_active:
            self.credential.errors.append(get_message("DISABLED_ACCOUNT")[0])
            return False

        verify = partial(
            webauthn.verify_authentication_response,
            credential=auth_cred,
            expected_challenge=self.challenge.encode(),
            expected_origin=_security._webauthn_util.origin(),
            expected_rp_id=request.host.split(":")[0],
            credential_public_key=self.cred.public_key,
            credential_current_sign_count=self.cred.sign_count,
        )
        # Start by verifying requiring user_verification - if that succeeds then
        # this authn could be used for both primary and secondary.
        # If it fails, then try to verify with user_verification == False - unless
        # as part of signin the app required user_verification (as stored in the state)
        try:
            self.authentication_verification = verify(require_user_verification=True)
            self.mf_check = True
        except InvalidAuthenticationResponse:
            try:
                self.authentication_verification = verify(
                    require_user_verification=self.user_verification
                )
            except InvalidAuthenticationResponse as exc:
                self.credential.errors.append(
                    get_message("WEBAUTHN_NO_VERIFY", cause=str(exc))[0]
                )
                return False
        return True


class WebAuthnDeleteForm(Form):
    name = StringField(
        get_form_field_xlate(_("Nickname")),
        validators=[Required(message="WEBAUTHN_NAME_REQUIRED")],
    )
    submit = SubmitField(label=get_form_field_label("delete"))

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False
        if not any([self.name.data == cred.name for cred in current_user.webauthn]):
            self.name.errors.append(
                get_message("WEBAUTHN_NAME_NOT_FOUND", name=self.name.data)[0]
            )
            return False
        return True


class WebAuthnVerifyForm(Form):
    submit = SubmitField(label=get_form_field_label("submit"), id="wan_verify")

    user: UserMixin

    def validate(self, **kwargs: t.Any) -> bool:
        if not super().validate(**kwargs):
            return False  # pragma: no cover
        # We are always authenticated - so return possible credentials.
        self.user = current_user
        return True


@auth_required(
    lambda: cv("API_ENABLED_METHODS"),
    within=lambda: cv("FRESHNESS"),
    grace=lambda: cv("FRESHNESS_GRACE_PERIOD"),
)
def webauthn_register() -> ResponseValue:
    """Start Registration for an existing authenticated user

    Note that it requires a POST to start the registration and must send 'name'
    in. We check here that user hasn't already registered an authenticator with that
    name.
    Also - this requires that the user already be logged in - so we can provide info
    as part of the GET that could otherwise be considered leaking user info.
    """
    payload: dict[str, t.Any]

    form: WebAuthnRegisterForm = t.cast(
        WebAuthnRegisterForm, build_form_from_request("wan_register_form")
    )

    if form.validate_on_submit():
        challenge = _security._webauthn_util.generate_challenge(
            cv("WAN_CHALLENGE_BYTES")
        )
        if not current_user.fs_webauthn_user_handle:
            # set a user handle. This allows an easy migration when adding this
            # column (and not requiring as part of schema change to update all existing
            # records. New users will have this set as part of user creation.
            after_this_request(view_commit)
            _datastore.set_webauthn_user_handle(current_user)

        ro = dict(
            challenge=challenge.encode(),
            rp_name=cv("WAN_RP_NAME"),
            rp_id=request.host.split(":")[0],
            user_id=current_user.fs_webauthn_user_handle.encode(),
            user_name=current_user.calc_username(),
            timeout=cv("WAN_REGISTER_TIMEOUT"),
            exclude_credentials=create_credential_list(
                current_user, ["first", "secondary"]
            ),
        )
        ro = _security._webauthn_util.registration_options(
            current_user, form.usage.data, ro
        )
        credential_options = webauthn.generate_registration_options(**ro)
        co_json = json.loads(webauthn.options_to_json(credential_options))
        co_json["extensions"] = {"credProps": True}

        # If we ask for UserVerification then we need to check that in the response.
        uv = False
        if credential_options.authenticator_selection:
            uv = (
                credential_options.authenticator_selection.user_verification
                == UserVerificationRequirement.REQUIRED
            )
        state = {
            "challenge": challenge,
            "name": form.name.data,
            "usage": form.usage.data,
            "user_verification": uv,
        }
        state_token = _security.wan_serializer.dumps(state)

        if _security._want_json(request):
            payload = {
                "credential_options": co_json,
                "wan_state": state_token,
            }
            return base_render_json(form, include_user=False, additional=payload)

        return _security.render_template(
            cv("WAN_REGISTER_TEMPLATE"),
            wan_register_form=form,
            wan_register_response_form=build_form("wan_register_response_form"),
            wan_state=state_token,
            credential_options=json.dumps(co_json),
            **_security._run_ctx_processor("wan_register"),
        )

    current_creds = []
    cred: WebAuthnMixin
    for cred in current_user.webauthn:
        cl = {
            "name": cred.name,
            "credential_id": bytes_to_base64url(cred.credential_id),
            "transports": cred.transports,
            "lastuse": cred.lastuse_datetime.isoformat(),
            "usage": cred.usage,
            "backup_state": (
                cred.backup_state if hasattr(cred, "backup_state") else False
            ),
            "device_type": (
                cred.device_type if hasattr(cred, "device_type") else "Unknown"
            ),
        }
        # TODO: i18n
        discoverable = "Unknown"
        if cred.extensions:
            extensions = json.loads(cred.extensions)
            if "credProps" in extensions:
                discoverable = extensions["credProps"].get("rk", "Unknown")
        cl["discoverable"] = discoverable
        current_creds.append(cl)

    payload = {"registered_credentials": current_creds}
    if _security._want_json(request):
        return base_render_json(form, additional=payload)
    return _security.render_template(
        cv("WAN_REGISTER_TEMPLATE"),
        wan_register_form=form,
        wan_delete_form=build_form("wan_delete_form"),
        registered_credentials=current_creds,
        **_security._run_ctx_processor("wan_register"),
    )


@auth_required(lambda: cv("API_ENABLED_METHODS"))
def webauthn_register_response(token: str) -> ResponseValue:
    """Response from browser."""
    form: WebAuthnRegisterResponseForm = t.cast(
        WebAuthnRegisterResponseForm,
        build_form_from_request("wan_register_response_form"),
    )

    expired, invalid, state = check_and_get_token_status(
        token, "wan", get_within_delta("WAN_REGISTER_WITHIN")
    )
    if invalid:
        m, c = get_message("API_ERROR")
    if expired:
        m, c = get_message("WEBAUTHN_EXPIRED", within=cv("WAN_REGISTER_WITHIN"))
    if invalid or expired:
        if _security._want_json(request):
            form.form_errors.append(m)
            return base_render_json(form, include_user=False)
        do_flash(m, c)
        return redirect(url_for_security("wan_register"))

    form.challenge = state["challenge"]
    form.name = state["name"]
    form.usage = state["usage"]
    form.user_verification = state["user_verification"]
    if form.validate_on_submit():
        # store away successful registration
        after_this_request(view_commit)
        _datastore.create_webauthn(
            current_user._get_current_object(),  # Not needed with Werkzeug >2.0.0
            name=state["name"],
            credential_id=form.registration_verification.credential_id,
            public_key=form.registration_verification.credential_public_key,
            sign_count=form.registration_verification.sign_count,
            backup_state=getattr(
                form.registration_verification, "credential_backed_up", False
            ),
            device_type=getattr(
                form.registration_verification,
                "credential_device_type",
                "single_device",
            ),
            transports=list(form.transports),
            extensions=form.extensions,
            usage=form.usage,
        )
        wan_registered.send(
            current_app._get_current_object(),  # type: ignore
            _async_wrapper=current_app.ensure_sync,  # type: ignore[arg-type]
            user=current_user,
            name=state["name"],
        )

        if _security._want_json(request):
            return base_render_json(form)
        msg, c = get_message("WEBAUTHN_REGISTER_SUCCESSFUL", name=state["name"])
        do_flash(msg, c)
        return redirect(get_url(cv("WAN_POST_REGISTER_VIEW")))

    if _security._want_json(request):
        return base_render_json(form)
    if form.errors:
        for v in form.errors.values():
            do_flash(v[0], "error")
    return redirect(url_for_security("wan_register"))


def _signin_common(user: UserMixin | None, usage: list[str]) -> tuple[t.Any, str]:
    """
    Common code between signin and verify - once form has been verified.
    """
    challenge = _security._webauthn_util.generate_challenge(cv("WAN_CHALLENGE_BYTES"))

    # Populate allowedCredentials if identity passed and allowed
    allow_credentials = None
    if user:
        allow_credentials = create_credential_list(user, usage)

    ao = dict(
        rp_id=request.host.split(":")[0],
        challenge=challenge.encode(),
        timeout=cv("WAN_SIGNIN_TIMEOUT"),
        allow_credentials=allow_credentials,
    )
    ao = _security._webauthn_util.authentication_options(user, usage, ao)
    options = webauthn.generate_authentication_options(**ao)

    # If we ask for UserVerification then we need to check that in the response.
    uv = False
    if options.user_verification == UserVerificationRequirement.REQUIRED:
        uv = True
    state = {
        "challenge": challenge,
        "user_verification": uv,
    }

    o_json = json.loads(webauthn.options_to_json(options))
    state_token = t.cast(  # type: ignore[redundant-cast]
        str, _security.wan_serializer.dumps(state)
    )
    return o_json, state_token


@anonymous_user_required
@unauth_csrf()
def webauthn_signin() -> ResponseValue:
    # This view can be called either as a 'first' authentication or as part of
    # 2FA.
    is_secondary = all(k in session for k in ["tf_user_id", "tf_state"]) and session[
        "tf_state"
    ] in ["ready"]
    if is_secondary or cv("WAN_ALLOW_AS_FIRST_FACTOR"):
        pass
    else:
        abort(404)

    form = t.cast(WebAuthnSigninForm, build_form_from_request("wan_signin_form"))
    form.is_secondary = is_secondary
    if form.validate_on_submit():
        o_json, state_token = _signin_common(
            form.user, ["secondary"] if is_secondary else ["first"]
        )
        if _security._want_json(request):
            payload = {
                "credential_options": o_json,
                "wan_state": state_token,
                "remember": form.remember.data,
                "is_secondary": is_secondary,
            }
            return base_render_json(form, include_user=False, additional=payload)

        # Copy the user's remember field into the next form - since that is
        # auto-submitted.
        return _security.render_template(
            cv("WAN_SIGNIN_TEMPLATE"),
            wan_signin_form=form,
            wan_signin_response_form=build_form(
                "wan_signin_response_form",
                remember=form.remember.data,
                next=form.next.data,
            ),
            wan_state=state_token,
            credential_options=json.dumps(o_json),
            is_secondary=is_secondary,
            **_security._run_ctx_processor("wan_signin"),
        )

    if _security._want_json(request):
        return base_render_json(form, additional={"is_secondary": is_secondary})
    return _security.render_template(
        cv("WAN_SIGNIN_TEMPLATE"),
        wan_signin_form=form,
        wan_signin_response_form=build_form("wan_signin_response_form"),
        is_secondary=is_secondary,
        **_security._run_ctx_processor("wan_signin"),
    )


@unauth_csrf()
def webauthn_signin_response(token: str) -> ResponseValue:
    is_secondary = all(k in session for k in ["tf_user_id", "tf_state"]) and session[
        "tf_state"
    ] in ["ready"]

    form = t.cast(
        WebAuthnSigninResponseForm, build_form_from_request("wan_signin_response_form")
    )

    expired, invalid, state = check_and_get_token_status(
        token, "wan", get_within_delta("WAN_SIGNIN_WITHIN")
    )
    if invalid:
        m, c = get_message("API_ERROR")
    if expired:
        m, c = get_message("WEBAUTHN_EXPIRED", within=cv("WAN_SIGNIN_WITHIN"))
    if invalid or expired:
        if _security._want_json(request):
            form.form_errors.append(m)
            return base_render_json(form, include_user=False)
        do_flash(m, c)
        return redirect(url_for_security("wan_signin"))

    form.challenge = state["challenge"]
    form.user_verification = state["user_verification"]
    form.is_secondary = is_secondary
    form.is_verify = False

    if form.validate_on_submit():
        # update last use and sign count
        after_this_request(view_commit)
        assert form.cred
        assert form.user
        form.cred.lastuse_datetime = _security.datetime_factory()
        form.cred.sign_count = form.authentication_verification.new_sign_count
        form.cred.backup_state = getattr(
            form.authentication_verification, "credential_backed_up", False
        )
        form.cred.device_type = getattr(
            form.authentication_verification, "credential_device_type", "single_device"
        )
        _datastore.put(form.cred)

        json_payload = {}
        if is_secondary:
            tf_token = _security.two_factor_plugins.tf_complete(form.user, True)
            if tf_token:
                after_this_request(
                    partial(tf_set_validity_token_cookie, token=tf_token)
                )
        else:
            # Need Two-factor?:
            #   - Is it required?
            #   - Did this credential provide 2-factor and
            #     is WAN_ALLOW_AS_MULTI_FACTOR set
            #   - Is another 2FA setup?
            remember_me = form.remember.data if "remember" in form else None
            if form.mf_check and cv("WAN_ALLOW_AS_MULTI_FACTOR"):
                pass
            else:
                response = _security.two_factor_plugins.tf_enter(
                    form.user,
                    remember_me,
                    "webauthn",
                    next_loc=propagate_next(request.url, form),
                )
                if response:
                    return response
            # login user
            login_user(form.user, remember=remember_me, authn_via=["webauthn"])

        goto_url = get_post_login_redirect()
        if _security._want_json(request):
            # Tell caller where we would go if forms based - they can use it or
            # not.
            json_payload["post_login_url"] = goto_url
            return base_render_json(
                form, include_auth_token=True, additional=json_payload
            )
        return redirect(goto_url)

    # Here on validate error
    if _security._want_json(request):
        return base_render_json(form)

    # Since the response is auto submitted - we go back to
    # signin form - for now use flash.
    if form.errors:
        for v in form.errors.values():
            do_flash(v[0], "error")
    return redirect(url_for_security("wan_signin"))


@auth_required(
    lambda: cv("API_ENABLED_METHODS"),
    within=lambda: cv("FRESHNESS"),
    grace=lambda: cv("FRESHNESS_GRACE_PERIOD"),
)
def webauthn_delete() -> ResponseValue:
    """Deletes an existing registered credential."""
    form = t.cast(WebAuthnDeleteForm, build_form_from_request("wan_delete_form"))

    if form.validate_on_submit():
        # validate made sure form.name.data exists.
        cred = [c for c in current_user.webauthn if c.name == form.name.data][0]
        after_this_request(view_commit)

        wan_deleted.send(
            current_app._get_current_object(),  # type: ignore
            _async_wrapper=current_app.ensure_sync,  # type: ignore[arg-type]
            user=current_user,
            name=cred.name,
        )
        _datastore.delete_webauthn(cred)
        if _security._want_json(request):
            return base_render_json(form)
        msg, c = get_message("WEBAUTHN_CREDENTIAL_DELETED", name=form.name.data)
        do_flash(msg, c)

    if _security._want_json(request):
        return base_render_json(form)
    if form.name.errors:
        do_flash(form.name.errors[0], "error")
    return redirect(url_for_security("wan_register"))


@auth_required(lambda: cv("API_ENABLED_METHODS"))
def webauthn_verify() -> ResponseValue:
    """
    Re-authenticate to reset freshness time.
    This is likely the result of a reauthn_handler redirect, which
    will have filled in ?next=xxx - which we want to carefully not lose as we
    go through these steps.
    """
    form = t.cast(WebAuthnVerifyForm, build_form_from_request("wan_verify_form"))

    if form.validate_on_submit():
        o_json, state_token = _signin_common(form.user, cv("WAN_ALLOW_AS_VERIFY"))
        if _security._want_json(request):
            payload = {"credential_options": o_json, "wan_state": state_token}
            return base_render_json(form, include_user=False, additional=payload)

        return _security.render_template(
            cv("WAN_VERIFY_TEMPLATE"),
            wan_verify_form=form,
            wan_signin_response_form=build_form("wan_signin_response_form"),
            wan_state=state_token,
            credential_options=json.dumps(o_json),
            **_security._run_ctx_processor("wan_verify"),
        )

    if _security._want_json(request):
        return base_render_json(form)
    return _security.render_template(
        cv("WAN_VERIFY_TEMPLATE"),
        wan_verify_form=form,
        wan_signin_response_form=build_form("wan_signin_response_form"),
        skip_login_menu=True,
        **_security._run_ctx_processor("wan_verify"),
    )


@auth_required(lambda: cv("API_ENABLED_METHODS"))
def webauthn_verify_response(token: str) -> ResponseValue:
    form = t.cast(
        WebAuthnSigninResponseForm, build_form_from_request("wan_signin_response_form")
    )

    expired, invalid, state = check_and_get_token_status(
        token, "wan", get_within_delta("WAN_SIGNIN_WITHIN")
    )
    if invalid:
        m, c = get_message("API_ERROR")
    if expired:
        m, c = get_message("WEBAUTHN_EXPIRED", within=cv("WAN_SIGNIN_WITHIN"))
    if invalid or expired:
        if _security._want_json(request):
            form.form_errors.append(m)
            return base_render_json(form, include_user=False)
        do_flash(m, c)
        return redirect(url_for_security("wan_verify"))

    form.challenge = state["challenge"]
    form.user_verification = state["user_verification"]
    form.is_secondary = False
    form.is_verify = True

    if form.validate_on_submit():
        # update last use and sign count
        after_this_request(view_commit)
        assert form.cred
        form.cred.lastuse_datetime = _security.datetime_factory()
        form.cred.sign_count = form.authentication_verification.new_sign_count
        _datastore.put(form.cred)

        # verified - so set freshness time.
        session["fs_paa"] = time.time()

        if _security._want_json(request):
            return base_render_json(form, include_auth_token=True)

        do_flash(*get_message("REAUTHENTICATION_SUCCESSFUL"))
        return redirect(get_post_verify_redirect())

    # Here on validate error (only POST is allowed on this endpoint)
    if _security._want_json(request):
        return base_render_json(form)

    # Since the response is auto submitted - we go back to
    # verify form - for now use flash.
    if form.credential.errors:
        do_flash(form.credential.errors[0], "error")
    return redirect(url_for_security("wan_verify"))


def is_cred_usable(cred: WebAuthnMixin, usage: str | list[str]) -> bool:
    # Return True is cred can be used for the requested usage/verify
    if not isinstance(usage, list):
        usage = [usage]
    assert "verify" not in usage
    return cred.usage in usage


def has_webauthn(user: UserMixin, usage: str | list[str]) -> bool:
    # Return True if ``user`` has one or more keys with requested usage.
    # Usage: either "first" or "secondary"
    if not isinstance(usage, list):
        usage = [usage]
    wan_keys = getattr(user, "webauthn", [])
    for cred in wan_keys:
        if is_cred_usable(cred, usage):
            return True
    return False


def create_credential_list(
    user: UserMixin, usage: list[str]
) -> list[PublicKeyCredentialDescriptor]:
    # Return a list of registered credentials - filtered by whether they apply to our
    # authentication state (first or secondary)
    cl = []

    for cred in user.webauthn:
        if not is_cred_usable(cred, usage):
            continue
        descriptor = PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY, id=cred.credential_id
        )
        if cred.transports:
            tlist = cred.transports
            transports = [AuthenticatorTransport(transport) for transport in tlist]
            descriptor.transports = transports
        # TODO order is important - figure out a way to add 'weight'
        cl.append(descriptor)

    return cl


class WebAuthnTfPlugin(TfPluginBase):
    def __init__(self, app: flask.Flask):
        super().__init__(app)

    def create_blueprint(
        self, app: flask.Flask, bp: flask.Blueprint, state: Security
    ) -> None:
        """Our endpoints are already registered since webauthn can be both
        a 'first' or 'secondary' authentication mechanism.
        """
        pass

    def get_setup_methods(self, user: UserMixin) -> list[str]:
        if has_webauthn(user, "secondary"):
            return [_("webauthn")]
        return []

    def tf_login(
        self, user: UserMixin, json_payload: dict[str, t.Any], next_loc: str | None
    ) -> ResponseValue:
        session["tf_state"] = "ready"
        if not _security._want_json(request):
            values = dict(next=next_loc) if next_loc else dict()
            return redirect(url_for_security("wan_signin", **values))

        # JSON response
        json_payload["tf_signin_url"] = url_for_security("wan_signin")
        json_payload["tf_state"] = "ready"
        json_payload["tf_method"] = "webauthn"
        return simple_render_json(additional=json_payload)
