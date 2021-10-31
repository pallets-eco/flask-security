"""
    flask_security.webauthn
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security WebAuthn module

    :copyright: (c) 2021-2021 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    This implements support for webauthn/FIDO2 using the py_webauthn package.

    Check out: https://golb.hplar.ch/2019/08/webauthn.html
    for some ideas on recovery and adding additional authenticators.

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
        - transports?
        - should we store things like user verified in 'last use'...

"""

import datetime
import secrets
import typing as t


from flask import after_this_request, request, session
from flask_login import current_user
from werkzeug.datastructures import MultiDict
from wtforms import BooleanField, StringField, SubmitField, ValidationError

try:
    import webauthn
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
    config_value as cv,
    do_flash,
    json_error_response,
    get_message,
    get_post_login_redirect,
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


class WebAuthnDeleteForm(Form):

    name = StringField(
        get_form_field_label("credential_nickname"), validators=[Required()]
    )
    submit = SubmitField(label=get_form_field_label("delete"))

    def validate(self):
        if not super().validate():
            return False
        return True


@auth_required(lambda: cv("API_ENABLED_METHODS"))
def webauthn_register() -> "ResponseValue":
    """Start Registration for an existing authenticated user

    Note that it requires a POST to start the registration and must send 'name'
    in. We check here that user hasn't already registered an authenticator with that
    name.
    Also - this requires that the user already be logged in - so we can provide info
    as part of the GET that could otherwise be considered leaking user info.
    """

    form_class = WebAuthnRegisterForm
    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    if form.validate_on_submit():
        challenge = secrets.token_urlsafe(cv("WAN_CHALLENGE_BYTES"))
        session["fs_wan_challenge"] = challenge

        credential_options = webauthn.generate_registration_options(
            challenge=challenge,
            rp_name=cv("WAN_RP_NAME"),
            rp_id=request.host.split(":")[0],
            user_id=current_user.fs_webauthn_uniquifier,
            user_name=current_user.calc_username(),
            timeout=cv("WAN_REGISTER_TIMEOUT"),
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
            ),
        )

        co_json = webauthn.options_to_json(credential_options)
        if _security._want_json(request):
            payload = {"credential_options": co_json}
            return base_render_json(form, include_user=False, additional=payload)

        # TODO - fix this add registered credentials?
        return _security.render_template(
            cv("WAN_REGISTER_TEMPLATE"),
            wan_register_form=form,
            wan_delete_form=_security.wan_delete_form(),
            credential_options=co_json,
        )

    current_creds = {}
    for cred in current_user.webauthn:
        current_creds[cred.name] = {
            "credential_id": bytes_to_base64url(cred.credential_id),
            "lastuse": cred.lastuse_datetime.isoformat(),
        }

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
def webauthn_register_response() -> "ResponseValue":
    """Response from browser.
    This comes via javascript and is JSON only...
    However we want all Flask-Security endpoints to have basic CSRF protection
    afforded by FlaskWTF (and not rely on the application to enable CSRFProtect).
    That happens magically when validating a form with a 'csrf_token' field.
    """

    form_class = WebAuthnRegisterForm
    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    challenge = session.get("fs_wan_challenge", None)
    if not challenge:
        # TODO - either add this to validate or handle forms.
        form.name.errors.append(get_message("API_ERROR")[0])
        return base_render_json(form, include_user=False)

    if form.validate_on_submit():
        try:
            # TODO should this be in the form validate?
            try:
                reg_cred = RegistrationCredential.parse_raw(request.data)
            except ValueError:
                raise ValidationError(message="API_ERROR")
            try:
                registration_verification = webauthn.verify_registration_response(
                    credential=reg_cred,
                    expected_challenge=challenge.encode(),
                    expected_origin=request.host_url.rstrip("/"),
                    expected_rp_id=request.host.split(":")[0],
                    require_user_verification=True,
                )

                # store away successful registration
                after_this_request(view_commit)
                _datastore.create_webauthn(
                    current_user,
                    name=form.name.data,
                    credential_id=registration_verification.credential_id,
                    public_key=registration_verification.credential_public_key,
                    sign_count=registration_verification.sign_count,
                )

                if _security._want_json(request):
                    return base_render_json(form)
                msg, c = get_message(
                    "WEBAUTHN_REGISTER_SUCCESSFUL", name=form.name.data
                )
                do_flash(msg, c)
                return redirect(url_for_security("wan_register"))

            except InvalidRegistrationResponse:
                raise ValidationError(message="API_ERROR")
        except ValidationError as e:
            msg, c = get_message(e.args[0])
            # Here on some error
            if _security._want_json(request):
                payload = json_error_response(errors=msg)
                return _security._render_json(payload, 400, None, None)
            return _security.render_template(
                cv("WAN_REGISTER_TEMPLATE"), wan_register_form=form
            )

    if _security._want_json(request):
        return base_render_json(form)
    return redirect(url_for_security("wan_register"))


@anonymous_user_required
@unauth_csrf(fall_through=True)
def webauthn_signin() -> "ResponseValue":
    form_class = WebAuthnSigninForm
    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    if form.validate_on_submit():
        challenge = secrets.token_urlsafe(cv("WAN_CHALLENGE_BYTES"))
        session["fs_wan_challenge"] = challenge

        options = webauthn.generate_authentication_options(
            rp_id=request.host.split(":")[0],
            challenge=challenge,
            timeout=cv("WAN_SIGNIN_TIMEOUT"),
            user_verification=UserVerificationRequirement.DISCOURAGED,
        )

        o_json = webauthn.options_to_json(options)
        if _security._want_json(request):
            payload = {"credential_options": o_json}
            return base_render_json(form, include_user=False, additional=payload)

        return _security.render_template(
            cv("WAN_SIGNIN_TEMPLATE"), wan_signin_form=form, credential_options=o_json
        )

    if _security._want_json(request):
        return base_render_json(form)
    return _security.render_template(cv("WAN_SIGNIN_TEMPLATE"), wan_signin_form=form)


@anonymous_user_required
@unauth_csrf(fall_through=True)
def webauthn_signin_response() -> "ResponseValue":
    """
    This comes via javascript and is JSON only...
    However we want all Flask-Security endpoints to have basic CSRF protection
    afforded by FlaskWTF (and not rely on the application to enable CSRFProtect.
    That happens magically when validating a form with a 'csrf_token' field.
    """
    form_class = WebAuthnSigninForm
    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()), meta=suppress_form_csrf())
        else:
            form = form_class(formdata=None, meta=suppress_form_csrf())
    else:
        form = form_class(meta=suppress_form_csrf())

    challenge = session.get("fs_wan_challenge", None)
    if not challenge:
        # TODO - either add this to validate or handle forms.
        payload = json_error_response(errors=get_message("API_ERROR")[0])
        return _security._render_json(payload, 400, None, None)

    if form.validate_on_submit():
        remember_me = form.remember.data if "remember" in form else None

        try:
            # TODO should this be in the form validate?
            try:
                auth_cred = AuthenticationCredential.parse_raw(request.data)
            except ValueError:
                raise ValidationError(message="API_ERROR")

            # Look up credential Id (raw_id) and user.
            cred = _datastore.find_webauthn(credential_id=auth_cred.raw_id)
            if not cred:
                raise ValidationError(message="WEBAUTHN_UNKNOWN_CREDENTIAL_ID")
            user = _datastore.find_user(id=cred.user_id)
            if not user:
                raise ValidationError(message="WEBAUTHN_ORPHAN_CREDENTIAL_ID")

            try:
                authentication_verification = webauthn.verify_authentication_response(
                    credential=auth_cred,
                    expected_challenge=challenge.encode(),
                    expected_origin=request.host_url.rstrip("/"),
                    expected_rp_id=request.host.split(":")[0],
                    credential_public_key=cred.public_key,
                    credential_current_sign_count=cred.sign_count,
                    require_user_verification=True,
                )

                # update last use and sign count
                after_this_request(view_commit)
                cred.lastuse_datetime = datetime.datetime.utcnow()
                cred.sign_count = authentication_verification.new_sign_count
                # TODO - store away authenticator DataFlags of this use?
                _datastore.put(cred)

                # login user
                login_user(user, remember=remember_me, authn_via=["webauthn"])

                goto_url = get_post_login_redirect()
                if _security._want_json(request):
                    # Tell caller where we would go if forms based - they can use it or
                    # not.
                    payload = {"post_login_url": goto_url}
                    return base_render_json(
                        form, include_auth_token=True, additional=payload
                    )

                return redirect(goto_url)

            except InvalidAuthenticationResponse:
                raise ValidationError(message="API_ERROR")
        except ValidationError as e:
            msg, c = get_message(e.args[0])
            # Here on some error
            if _security._want_json(request):
                payload = json_error_response(errors=msg)
                return _security._render_json(payload, 400, None, None)
            do_flash(msg, c)
            return redirect(url_for_security("wan_signin"))

    if _security._want_json(request):
        return base_render_json(form)
    return _security.render_template(cv("WAN_SIGNIN_TEMPLATE"), wan_register_form=form)


@auth_required(lambda: cv("API_ENABLED_METHODS"))
def webauthn_delete() -> "ResponseValue":
    """Deletes an existing registered credential."""

    form_class = WebAuthnDeleteForm
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
        # TODO - errors, json

    return redirect(url_for_security("wan_register"))
