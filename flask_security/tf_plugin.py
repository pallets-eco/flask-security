"""
    flask_security.tf_plugin
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security Two-Factor Plugin Module

    :copyright: (c) 2022-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    TODO:
        - add localized callback for select choices.
"""

from __future__ import annotations

import typing as t

from flask import request, redirect, session

from .decorators import unauth_csrf
from .forms import (
    build_form_from_request,
    get_form_field_xlate,
    Form,
    RadioField,
    SubmitField,
)
from .proxies import _datastore, _security
from .utils import (
    _,
    base_render_json,
    check_and_get_token_status,
    config_value as cv,
    do_flash,
    get_message,
    get_within_delta,
    get_url,
    login_user,
    propagate_next,
    simple_render_json,
    url_for_security,
)

if t.TYPE_CHECKING:  # pragma: no cover
    import flask
    from flask.typing import ResponseValue
    from flask import Response
    from flask_security import Security, UserMixin


class TwoFactorSelectForm(Form):
    which = RadioField(get_form_field_xlate(_("Available Second Factor Methods:")))
    submit = SubmitField(get_form_field_xlate(_("Select")))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


@unauth_csrf()
def tf_select() -> ResponseValue:
    # Ask user which MFA method they want to use.
    # This is used when a user has setup more than one type of 2FA.
    form = t.cast(
        TwoFactorSelectForm, build_form_from_request("two_factor_select_form")
    )

    # This endpoint is unauthenticated - make sure we're in a valid state
    if not all(k in session for k in ["tf_user_id", "tf_select"]):
        # illegal call on this endpoint
        tf_clean_session()
        return tf_illegal_state(form, cv("TWO_FACTOR_ERROR_VIEW"))

    user = _datastore.find_user(fs_uniquifier=session["tf_user_id"])
    if not user:  # pragma no cover
        # hard to imagine - someone deletes the user while they are logging in.
        tf_clean_session()
        return tf_illegal_state(form, cv("TWO_FACTOR_ERROR_VIEW"))

    setup_methods = _security.two_factor_plugins.get_setup_tf_methods(user)
    form.which.choices = setup_methods

    if form.validate_on_submit():
        response = None
        tf_impl = _security.two_factor_plugins.method_to_impl(user, form.which.data)
        if tf_impl:
            json_payload = {"tf_required": True}
            response = tf_impl.tf_login(
                user, json_payload, next_loc=propagate_next(request.url, None)
            )
        if not response:  # pragma no cover
            # This really can't happen unless between the time the started logging in
            # and now, they deleted a second factor (which they would have to do
            # in another window).
            tf_clean_session()
            return tf_illegal_state(form, cv("TWO_FACTOR_ERROR_VIEW"))
        return response

    if _security._want_json(request):
        payload = {"tf_select": True, "tf_setup_methods": setup_methods}
        return base_render_json(form, include_user=False, additional=payload)

    return _security.render_template(
        cv("TWO_FACTOR_SELECT_TEMPLATE"),
        two_factor_select_form=form,
        **_security._run_ctx_processor("tf_select"),
    )


class TfPluginBase:  # pragma no cover
    def __init__(self, app: flask.Flask):
        pass

    def create_blueprint(
        self, app: flask.Flask, bp: flask.Blueprint, state: Security
    ) -> None:
        raise NotImplementedError

    def get_setup_methods(self, user: UserMixin) -> list[str]:
        """
        Return a list of methods that ``user`` has setup for this second factor
        """
        raise NotImplementedError

    def tf_login(
        self, user: UserMixin, json_payload: dict[str, t.Any], next_loc: str | None
    ) -> ResponseValue:
        """
        Called from first/primary authenticated views if the user successfully
        authenticated, and required a second method of authentication.
        This method returns the necessary information for the user UI to continue.
        For forms, this is usually a redirect to a secondary sign in form. For JSON
        it is just a payload that describes what the user has to do next.
        """
        raise NotImplementedError


class TfPlugin:
    """
    Two-Factor plugin support.

    Enables multiple independent two-factor implementations to be configured for a given
    app. See TfPluginBase for what a new implementation must provide.
    """

    def __init__(self) -> None:
        self._tf_impls: dict[str, TfPluginBase] = {}

    def register_tf_impl(
        # N.B. all methods must be unique across all implementations.
        self,
        app: flask.Flask,
        name: str,
        impl: t.Type[TfPluginBase],
    ) -> None:
        self._tf_impls[name] = impl(app)

    def create_blueprint(
        self, app: flask.Flask, bp: flask.Blueprint, state: Security
    ) -> None:
        if state.support_mfa:
            for impl in self._tf_impls.values():
                impl.create_blueprint(app, bp, state)
            # Add our route for selecting between multiple active two-factor
            # mechanisms.
            bp.route(
                cv("TWO_FACTOR_SELECT_URL", app),
                methods=["GET", "POST"],
                endpoint="tf_select",
            )(tf_select)

    def method_to_impl(self, user: UserMixin, method: str) -> TfPluginBase | None:
        # reverse map a method to the implementation.
        # N.B. again - requires that methods be unique across all implementations.
        # There is a small window that a previously setup method was removed.
        for impl in self._tf_impls.values():
            setup_methods = impl.get_setup_methods(user)
            if method in setup_methods:
                return impl
        return None  # pragma no cover

    def get_setup_tf_methods(self, user: UserMixin) -> list[str]:
        # Return list of methods that user has setup
        methods = []
        for impl in self._tf_impls.values():
            methods.extend(impl.get_setup_methods(user))
        return methods

    def tf_enter(
        self,
        user: UserMixin,
        remember_me: bool,
        primary_authn_via: str,
        next_loc: str | None,
    ) -> ResponseValue | None:
        """Check if two-factor is required and if so, start the process.
        Must be called in a request context.
        remember_me controls 2 cookies - the remember_me cookie and the tf_validity
        cookie. We use the session to hold the fact that the user requested 'remember'
        across the second factor.
        """
        json_payload: dict[str, t.Any]
        if _security.support_mfa:
            tf_setup_methods = self.get_setup_tf_methods(user)
            if cv("TWO_FACTOR_REQUIRED") or len(tf_setup_methods) > 0:
                tf_fresh = tf_verify_validity_token(user.fs_uniquifier)
                if cv("TWO_FACTOR_ALWAYS_VALIDATE") or not tf_fresh:
                    # Clean out any potential old session info - in case of previous
                    # aborted 2FA attempt.
                    tf_clean_session()

                    json_payload = {"tf_required": True}
                    if remember_me:
                        session["tf_remember_login"] = remember_me

                    session["tf_user_id"] = user.fs_uniquifier
                    # A backwards compat hack - the original twofactor could be setup
                    # as part of initial login.
                    if len(tf_setup_methods) == 0:
                        # only initial two-factor implementation supports this
                        return self._tf_impls["code"].tf_login(
                            user, json_payload, next_loc
                        )
                    elif len(tf_setup_methods) == 1:
                        # method_to_impl can't return None here since we just
                        # got the methods up above.
                        impl = t.cast(
                            TfPluginBase,
                            self.method_to_impl(user, tf_setup_methods[0]),
                        )
                        return impl.tf_login(user, json_payload, next_loc)
                    else:
                        session["tf_select"] = True
                        if not _security._want_json(request):
                            values = dict(next=next_loc) if next_loc else dict()
                            return redirect(url_for_security("tf_select", **values))
                        # Let's force app to go through tf-select just in case we want
                        # to do further validation... However, provide the choices
                        # so they can just do a POST
                        json_payload.update(
                            {
                                "tf_select": True,
                                "tf_setup_methods": tf_setup_methods,
                            }
                        )
                        return simple_render_json(json_payload)
        return None

    def tf_complete(self, user: UserMixin, dologin: bool) -> str | None:
        remember = session.pop("tf_remember_login", None)

        if dologin:
            login_user(user, remember=remember)
        tf_clean_session()
        token = None
        # return a token to avoid future two-factor prompts (for a period of time)
        if not cv("TWO_FACTOR_ALWAYS_VALIDATE") and remember:
            token = generate_tf_validity_token(user.fs_uniquifier)
        return token


def generate_tf_validity_token(fs_uniquifier):
    """Generates a unique token for the specified user.

    :param fs_uniquifier: The fs_uniquifier of a user to whom the token belongs to
    """
    return _security.tf_validity_serializer.dumps(fs_uniquifier)


def tf_validity_token_status(token):
    """Returns the expired status, invalid status, and user of a
    Two-Factor Validity token.
    For example::

        expired, invalid, user = tf_validity_token_status('...')

    :param token: The Two-Factor Validity token
    """
    return check_and_get_token_status(
        token, "tf_validity", get_within_delta("TWO_FACTOR_LOGIN_VALIDITY")
    )


def tf_verify_validity_token(fs_uniquifier: str) -> bool:
    """Returns the status of the Two-Factor Validity token based on the current
    request.

    :param fs_uniquifier: The ``fs_uniquifier`` of the submitting user.
    """
    token = request.cookies.get("tf_validity", default=None)
    if token is None:
        return False

    expired, invalid, uniquifier = tf_validity_token_status(token)
    if expired or invalid or (fs_uniquifier != uniquifier):
        return False

    return True


def tf_set_validity_token_cookie(response: Response, token: str) -> Response:
    """Sets the Two-Factor validity token for a specific user given that is
    configured and the user selects remember me

    :param response: The response with which to set the set_cookie
    :param token: validity token
    """
    cookie_kwargs = cv("TWO_FACTOR_VALIDITY_COOKIE")
    max_age = int(get_within_delta("TWO_FACTOR_LOGIN_VALIDITY").total_seconds())
    response.set_cookie("tf_validity", value=token, max_age=max_age, **cookie_kwargs)
    # This is likely overkill since so far we only return this on a POST which is
    # unlikely to be cached.
    response.vary.add("Cookie")
    return response


def tf_check_state(allowed_states: list[str]) -> UserMixin | None:
    if (
        not all(k in session for k in ["tf_user_id", "tf_state"])
        or session["tf_state"] not in allowed_states
    ):
        tf_clean_session()
        return None

    user = _datastore.find_user(fs_uniquifier=session["tf_user_id"])
    if not user:
        tf_clean_session()
    return user


def tf_illegal_state(form, redirect_to):
    m, c = get_message("TWO_FACTOR_PERMISSION_DENIED")
    if not _security._want_json(request):
        do_flash(m, c)
        return redirect(get_url(redirect_to))
    else:
        form.form_errors.append(m)
        return base_render_json(form, include_user=False)


def tf_clean_session():
    """
    Clean out ALL stuff stored in session (e.g. on logout or restart of a session)
    """
    if cv("TWO_FACTOR"):
        for k in [
            "tf_state",
            "tf_user_id",
            "tf_primary_method",
            "tf_remember_login",
            "tf_totp_secret",
            "tf_select",
        ]:
            session.pop(k, None)
