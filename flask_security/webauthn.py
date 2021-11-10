"""
    flask_security.webauthn
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security WebAuthn module

    :copyright: (c) 2021-2021 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    This implements support for webauthn/FIDO2 using the py_webauthn package.

    Check out: https://golb.hplar.ch/2019/08/webauthn.html
    for some ideas on recovery and adding additional authenticators.

    For testing - you can see your YubiKey (or other) resident keys in chrome!
    chrome://settings/securityKeys

    TODO:
        - deal with fs_webauthn_uniquifier for existing users
        - add webauthn to other datastores
        - unit tests!
        - docs!
        - openapi.yml
        - add signals
        - integrate with unified signin?
        - make sure reset functions reset fs_webauthn - and remove credentials?
        - context processors
        - add config variables for Origin and RP_ID?
        - Add signin form option to add username so we can return allowedCredentials
          but make this an option since it enables leaking of user info.
        - update/add examples to support webauthn
        - does remember me make sense?
        - should we store things like user verified in 'last use'...
        - config for allow as Primary, allow as Primary/MFA
        - some options to request user verification and check on register - i.e.
          'I want a two-factor capable key'

"""

import datetime
import json
import secrets
import typing as t


from flask import after_this_request, request
from flask_login import current_user
from werkzeug.datastructures import MultiDict
from wtforms import BooleanField, HiddenField, StringField, SubmitField

try:
    import webauthn
    from webauthn.authentication.verify_authentication_response import (
        VerifiedAuthentication,
    )
    from webauthn.registration.verify_registration_response import VerifiedRegistration
    from webauthn.helpers.exceptions import (
        InvalidAuthenticationResponse,
        InvalidRegistrationResponse,
    )
    from webauthn.helpers.structs import (
        AuthenticationCredential,
        AuthenticatorSelectionCriteria,
        RegistrationCredential,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )
    from webauthn.helpers import bytes_to_base64url
except ImportError:
    pass

from .decorators import anonymous_user_required, auth_required, unauth_csrf
from .forms import Form, Required, get_form_field_label
from .proxies import _security, _datastore
from .quart_compat import get_quart_status
from .utils import (
    base_render_json,
    check_and_get_token_status,
    config_value as cv,
    do_flash,
    json_error_response,
    get_message,
    get_post_login_redirect,
    get_within_delta,
    login_user,
    suppress_form_csrf,
    url_for_security,
    view_commit,
)

if t.TYPE_CHECKING:  # pragma: no cover
    from flask.typing import ResponseValue

if get_quart_status():  # pragma: no cover
    from quart import redirect
else:
    from flask import redirect


class WebAuthnRegisterForm(Form):

    name = StringField(
        get_form_field_label("credential_nickname"), validators=[Required()]
    )
    submit = SubmitField(label=get_form_field_label("submit"), id="wan_register")

    def validate(self):
        if not super().validate():
            return False
        if _datastore.find_webauthn(name=self.name.data):
            msg = get_message("WEBAUTHN_NAME_INUSE", name=self.name.data)[0]
            self.name.errors.append(msg)
            return False
        return True


class WebAuthnRegisterResponseForm(Form):
    credential = HiddenField()
    submit = SubmitField(label=get_form_field_label("submit"))

    # from state
    challenge: str
    name: str
    # this is returned to caller (not part of the client form)
    registration_verification: "VerifiedRegistration"
    transports: t.List[str] = []
    extensions: str

    def validate(self) -> bool:
        if not super().validate():
            return False
        if _datastore.find_webauthn(name=self.name):
            msg = get_message("WEBAUTHN_NAME_INUSE", name=self.name)[0]
            self.credential.errors.append(msg)
            return False
        try:
            reg_cred = RegistrationCredential.parse_raw(self.credential.data)
        except ValueError:
            self.credential.errors.append(get_message("API_ERROR"))
            return False
        try:
            self.registration_verification = webauthn.verify_registration_response(
                credential=reg_cred,
                expected_challenge=self.challenge.encode(),
                expected_origin=request.host_url.rstrip("/"),
                expected_rp_id=request.host.split(":")[0],
                require_user_verification=True,
            )
            if _datastore.find_webauthn(credential_id=reg_cred.raw_id):
                msg = get_message("WEBAUTHN_CREDENTIALID_INUSE")[0]
                self.credential.errors.append(msg)
                return False
        except InvalidRegistrationResponse:
            self.credential.errors.append(get_message("API_ERROR"))
            return False
        self.transports = reg_cred.transports
        # Alas py_webauthn doesn't support extensions yet - so we have to dig in
        response_full = json.loads(self.credential.data)
        # TODO - verify this is JSON
        self.extensions = response_full.get("extensions", None)
        return True


class WebAuthnSigninForm(Form):

    remember = BooleanField(get_form_field_label("remember_me"))
    submit = SubmitField(label=get_form_field_label("submit"), id="wan_signin")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.remember.default = cv("DEFAULT_REMEMBER_ME")

    def validate(self):
        if not super().validate():
            return False
        return True


class WebAuthnSigninResponseForm(Form):
    submit = SubmitField(label=get_form_field_label("submit"))
    credential = HiddenField()

    # returned to caller
    authentication_verification: "VerifiedAuthentication"
    user = None
    cred = None

    def validate(self) -> bool:
        if not super().validate():
            return False
        try:
            auth_cred = AuthenticationCredential.parse_raw(self.credential.data)
        except ValueError:
            self.credential.errors.append(get_message("API_ERROR"))
            return False

        # Look up credential Id (raw_id) and user.
        self.cred = _datastore.find_webauthn(credential_id=auth_cred.raw_id)
        if not self.cred:
            self.credential.errors.append(get_message("WEBAUTHN_UNKNOWN_CREDENTIAL_ID"))
            return False
        self.user = _datastore.find_user(id=self.cred.user_id)
        if not self.user:
            self.credential.errors.append(get_message("WEBAUTHN_ORPHAN_CREDENTIAL_ID"))
            return False

        try:
            self.authentication_verification = webauthn.verify_authentication_response(
                credential=auth_cred,
                expected_challenge=self.challenge.encode(),
                expected_origin=request.host_url.rstrip("/"),
                expected_rp_id=request.host.split(":")[0],
                credential_public_key=self.cred.public_key,
                credential_current_sign_count=self.cred.sign_count,
                require_user_verification=True,
            )
        except InvalidAuthenticationResponse:
            self.credential.errors.append(get_message("API_ERROR"))
            return False
        return True


class WebAuthnDeleteForm(Form):

    name = StringField(
        get_form_field_label("credential_nickname"), validators=[Required()]
    )
    submit = SubmitField(label=get_form_field_label("delete"))

    def validate(self):
        if not super().validate():
            return False
        return True


@auth_required(
    lambda: cv("API_ENABLED_METHODS"),
    within=lambda: cv("FRESHNESS"),
    grace=lambda: cv("FRESHNESS_GRACE_PERIOD"),
)
def webauthn_register() -> "ResponseValue":
    """Start Registration for an existing authenticated user

    Note that it requires a POST to start the registration and must send 'name'
    in. We check here that user hasn't already registered an authenticator with that
    name.
    Also - this requires that the user already be logged in - so we can provide info
    as part of the GET that could otherwise be considered leaking user info.
    """
    payload: t.Dict[str, t.Any]

    form_class: t.Type[WebAuthnRegisterForm] = _security.wan_register_form
    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    if form.validate_on_submit():
        challenge = secrets.token_urlsafe(cv("WAN_CHALLENGE_BYTES"))
        state = {"challenge": challenge, "name": form.name.data}

        # TODO make authenticator selection a call back so app can set whatever
        # it needs?
        credential_options = webauthn.generate_registration_options(
            challenge=challenge,
            rp_name=cv("WAN_RP_NAME"),
            rp_id=request.host.split(":")[0],
            user_id=current_user.fs_webauthn_uniquifier,
            user_name=current_user.calc_username(),
            timeout=cv("WAN_REGISTER_TIMEOUT"),
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.DISCOURAGED,
            ),
        )
        #
        co_json = json.loads(webauthn.options_to_json(credential_options))
        co_json["extensions"] = {"credProps": True}

        state_token = _security.wan_serializer.dumps(state)

        if _security._want_json(request):
            payload = {
                "credential_options": json.dumps(co_json),
                "wan_state": state_token,
            }
            return base_render_json(form, include_user=False, additional=payload)

        return _security.render_template(
            cv("WAN_REGISTER_TEMPLATE"),
            wan_register_form=form,
            wan_register_response_form=WebAuthnRegisterResponseForm(),
            wan_state=state_token,
            credential_options=json.dumps(co_json),
        )

    current_creds = {}
    for cred in current_user.webauthn:
        current_creds[cred.name] = {
            "credential_id": bytes_to_base64url(cred.credential_id),
            "transports": cred.transports,
            "lastuse": cred.lastuse_datetime.isoformat(),
        }
        # TODO: i18n
        discoverable = "Unknown"
        if cred.extensions:
            extensions = json.loads(cred.extensions)
            if "credProps" in extensions:
                discoverable = extensions["credProps"].get("rk", "Unknown")
        current_creds[cred.name]["discoverable"] = discoverable

    payload = {"registered_credentials": current_creds}
    if _security._want_json(request):
        return base_render_json(form, additional=payload)
    # TODO context processors
    return _security.render_template(
        cv("WAN_REGISTER_TEMPLATE"),
        wan_register_form=form,
        wan_delete_form=_security.wan_delete_form(),
        registered_credentials=current_creds,
    )


@auth_required(lambda: cv("API_ENABLED_METHODS"))
def webauthn_register_response(token: str) -> "ResponseValue":
    """Response from browser."""

    form_class: t.Type[
        WebAuthnRegisterResponseForm
    ] = _security.wan_register_response_form
    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    expired, invalid, state = check_and_get_token_status(
        token, "wan", get_within_delta("WAN_REGISTER_WITHIN")
    )
    if invalid:
        m, c = get_message("API_ERROR")
    if expired:
        m, c = get_message("WAN_EXPIRED", within=cv("WAN_REGISTER_WITHIN"))
    if invalid or expired:
        if _security._want_json(request):
            payload = json_error_response(errors=m)
            return _security._render_json(payload, 400, None, None)
        do_flash(m, c)
        return redirect(url_for_security("wan_register"))

    form.challenge = state["challenge"]
    form.name = state["name"]
    if form.validate_on_submit():

        # store away successful registration
        after_this_request(view_commit)

        # convert transports to comma separated
        transports = ",".join(tr.value for tr in form.transports)

        _datastore.create_webauthn(
            current_user,
            name=state["name"],
            credential_id=form.registration_verification.credential_id,
            public_key=form.registration_verification.credential_public_key,
            sign_count=form.registration_verification.sign_count,
            transports=transports,
            extensions=form.extensions,
        )

        if _security._want_json(request):
            return base_render_json(form)
        msg, c = get_message("WEBAUTHN_REGISTER_SUCCESSFUL", name=state["name"])
        do_flash(msg, c)
        return redirect(url_for_security("wan_register"))

    if _security._want_json(request):
        return base_render_json(form)
    # TODO flash error....
    return redirect(url_for_security("wan_register"))


@anonymous_user_required
@unauth_csrf(fall_through=True)
def webauthn_signin() -> "ResponseValue":
    form_class: t.Type[WebAuthnSigninForm] = _security.wan_signin_form
    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    if form.validate_on_submit():
        challenge = secrets.token_urlsafe(cv("WAN_CHALLENGE_BYTES"))
        state = {
            "challenge": challenge,
        }

        options = webauthn.generate_authentication_options(
            rp_id=request.host.split(":")[0],
            challenge=challenge,
            timeout=cv("WAN_SIGNIN_TIMEOUT"),
            user_verification=UserVerificationRequirement.DISCOURAGED,
        )

        o_json = webauthn.options_to_json(options)
        state_token = _security.wan_serializer.dumps(state)
        if _security._want_json(request):
            payload = {"credential_options": o_json, "wan_state": state_token}
            return base_render_json(form, include_user=False, additional=payload)

        return _security.render_template(
            cv("WAN_SIGNIN_TEMPLATE"),
            wan_signin_form=form,
            wan_signin_response_form=WebAuthnSigninResponseForm(),
            wan_state=state_token,
            credential_options=o_json,
        )

    if _security._want_json(request):
        return base_render_json(form)
    return _security.render_template(
        cv("WAN_SIGNIN_TEMPLATE"),
        wan_signin_form=form,
        wan_signin_response_form=WebAuthnSigninResponseForm(),
    )


@anonymous_user_required
@unauth_csrf(fall_through=True)
def webauthn_signin_response(token: str) -> "ResponseValue":
    form_class: t.Type[WebAuthnSigninResponseForm] = _security.wan_signin_response_form
    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    expired, invalid, state = check_and_get_token_status(
        token, "wan", get_within_delta("WAN_SIGNIN_WITHIN")
    )
    if invalid:
        m, c = get_message("API_ERROR")
    if expired:
        m, c = get_message("WAN_EXPIRED", within=cv("WAN_SIGNIN_WITHIN"))
    if invalid or expired:
        if _security._want_json(request):
            payload = json_error_response(errors=m)
            return _security._render_json(payload, 400, None, None)
        do_flash(m, c)
        return redirect(url_for_security("wan_signin"))

    form.challenge = state["challenge"]

    if form.validate_on_submit():
        remember_me = form.remember.data if "remember" in form else None

        # update last use and sign count
        after_this_request(view_commit)
        form.cred.lastuse_datetime = datetime.datetime.utcnow()
        form.cred.sign_count = form.authentication_verification.new_sign_count
        _datastore.put(form.cred)

        # login user
        login_user(form.user, remember=remember_me, authn_via=["webauthn"])

        goto_url = get_post_login_redirect()
        if _security._want_json(request):
            # Tell caller where we would go if forms based - they can use it or
            # not.
            payload = {"post_login_url": goto_url}
            return base_render_json(form, include_auth_token=True, additional=payload)
        return redirect(goto_url)

    if _security._want_json(request):
        return base_render_json(form)

    # Here on validate error - since the response is auto submitted - we go back to
    # signin form - for now use flash.
    # TODO set into a special form element error?
    signin_form = _security.wan_signin_form()
    if form.credential.errors:
        m, c = form.credential.errors[0]
        do_flash(m, c)
    return _security.render_template(
        cv("WAN_SIGNIN_TEMPLATE"), wan_signin_form=signin_form
    )


@auth_required(lambda: cv("API_ENABLED_METHODS"))
def webauthn_delete() -> "ResponseValue":
    """Deletes an existing registered credential."""

    form_class: t.Type[WebAuthnDeleteForm] = _security.wan_delete_form
    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    if form.validate_on_submit():
        cred = _datastore.find_webauthn(name=form.name.data)
        if cred:
            after_this_request(view_commit)
            _datastore.delete_webauthn(cred)
        # TODO - errors, json, flash

    return redirect(url_for_security("wan_register"))
