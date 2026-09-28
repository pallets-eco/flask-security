"""
flask_security.model_mixins
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Flask-Security mixins for database models.

These are used by appliactions to build their class User.
Note that methods defined here shoudl NOT perform datastore operations.

:copyright: (c) 2026-2026 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.
"""

from __future__ import annotations

from datetime import datetime
import time
import typing as t

from .proxies import current_app, _security
from .signals import user_failed_authn
from .twofactor import tf_send_security_token
from .unified_signin import us_send_security_token
from .utils import (
    _config_value as cv,
    get_message,
    get_identity_attributes,
    verify_and_update_password,
)

if t.TYPE_CHECKING:  # pragma: no cover
    # flask_login isn't typed yet
    class BaseUserMixin:
        # __hash__ = object.__hash__

        @property
        def is_active(self) -> bool:
            return True

        @property
        def is_authenticated(self) -> bool:
            return self.is_active

        @property
        def is_anonymous(self) -> bool:
            return False

        def get_id(self) -> str: ...

        def __eq__(self, other: object) -> bool:
            """
            Checks the equality of two `UserMixin` objects using `get_id`.
            """
            if isinstance(other, UserMixin):
                return self.get_id() == other.get_id()
            return NotImplemented

        def __ne__(self, other: object) -> bool:
            """
            Checks the inequality of two `UserMixin` objects using `get_id`.
            """
            equal = self.__eq__(other)
            if equal is NotImplemented:
                return NotImplemented
            return not equal

else:
    from flask_login import UserMixin as BaseUserMixin


class RoleMixin:
    """Mixin for `Role` model definitions"""

    if t.TYPE_CHECKING:  # pragma: no cover
        id: int
        name: str
        description: str | None
        permissions: list[str] | None
        update_datetime: datetime

        def __init__(self, **kwargs: t.Any): ...

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RoleMixin) or isinstance(other, str):
            return self.name == other or self.name == getattr(other, "name", None)
        return NotImplemented  # pragma: no cover

    def __ne__(self, other: object) -> bool:
        if isinstance(other, RoleMixin) or isinstance(other, str):
            return not self.__eq__(other)
        return NotImplemented  # pragma: no cover

    def __hash__(self) -> int:
        return hash(self.name)  # pragma: no cover

    def get_permissions(self) -> set[str]:
        """
        Return set of permissions associated with role.

        .. versionadded:: 3.3.0
        """
        if hasattr(self, "permissions") and self.permissions:
            return set(self.permissions)
        return set()


class UserMixin(BaseUserMixin):
    """Mixin for `User` model definitions"""

    if t.TYPE_CHECKING:  # pragma: no cover
        # These are defined in the application's Model files.
        id: int
        email: str
        username: str | None
        password: str | None
        active: bool
        fs_uniquifier: str
        fs_token_uniquifier: str
        fs_webauthn_user_handle: str
        confirmed_at: datetime | None
        last_login_at: datetime
        current_login_at: datetime
        last_login_ip: str | None
        current_login_ip: str | None
        login_count: int
        tf_primary_method: str | None
        tf_totp_secret: str | None
        tf_phone_number: str | None
        mf_recovery_codes: list[str] | None
        us_phone_number: str | None
        us_totp_secrets: str | bytes | None
        create_datetime: datetime
        update_datetime: datetime
        roles: list[RoleMixin]
        webauthn: list[WebAuthnMixin]
        refresh_trackers: list[RefreshTrackerMixin]

        def __init__(self, **kwargs: t.Any): ...

    def get_id(self) -> str:
        """Returns the user identification attribute. 'Alternative-token' for
        Flask-Login. This is always ``fs_uniquifier``.

        .. versionadded:: 3.4.0
        """
        return str(self.fs_uniquifier)

    @property
    def is_active(self) -> bool:
        """Returns `True` if the user is active."""
        return self.active

    def get_auth_token(self) -> str | bytes:
        """Constructs the user's authentication token.

        :raises ValueError: If ``fs_token_uniquifier`` is part of model but not set.

        Uses ``fs_uniquifier`` or ``fs_token_uniquifier`` (if in the UserModel)
        to identify this user. If ``fs_token_uniquifier`` is used then
        changing password doesn't invalidate auth tokens.

        Calls :meth:`.UserMixin.augment_auth_token` which applications can override
        to add any additional information.

        The returned value is securely signed using the ``remember_token_serializer``

        .. versionchanged:: 4.0.0
            If user model has ``fs_token_uniquifier`` - use that (raise ValueError
            if not set). Otherwise, fallback to using ``fs_uniquifier``.
        .. versionchanged:: 5.4.0
            New format - a dict with a version string. Add a token-based expiry
            option as well as a session id.
        .. versionchanged:: 5.5.0
            Remove session id (never set or used); added fs_paa (last authentication
            timestamp)
        """
        from .proxies import _datastore

        uid = getattr(self, _datastore.get_token_uniquifier_name())
        if not uid:
            raise ValueError()
        tdata: dict[str, t.Any] = {
            "ver": str(5),
            "uid": uid,
            "fs_paa": time.time(),  # equivalent of session["fs_paa"]
            "exp": int(cv("TOKEN_EXPIRE_TIMESTAMP")(self)),  # if >0 then shorter of
            # :data:SECURITY_MAX_AGE and this.
        }
        # Let application add things
        self.augment_auth_token(tdata)

        # Serialize and sign
        return _security.remember_token_serializer.dumps(tdata)

    def augment_auth_token(self, tdata: dict[str, t.Any]) -> None:
        """Override this to add/modify parts of the auth token.
        Additions to the dict can be made here and verified in
        :meth:`.UserMixin.verify_auth_token`

        .. versionadded:: 5.4.0
        """
        return

    def verify_auth_token(self, tdata: dict[str, t.Any]) -> bool:
        """
        Override this to perform additional verification of contents of auth token.
        Prior to this being called the token has been validated (via signing)
        and has not expired (either with MAX_AGE or specific 'exp' value).

        :param tdata: a dictionary just as in augment_auth_token()
        :return: True if auth token represented by tdata is valid, False otherwise.

        .. versionadded:: 3.3.0

        .. versionchanged:: 5.4.0
            Now receives a dictionary.
        """
        return True

    def has_role(self, role: str | RoleMixin) -> bool:
        """Returns `True` if the user identifies with the specified role.

        :param role: A role name or `Role` instance"""
        if isinstance(role, str):
            return role in (role.name for role in self.roles)
        else:
            return role in self.roles

    def has_permission(self, permission: str) -> bool:
        """
        Returns `True` if user has this permission (via a role it has).

        :param permission: permission string name

        .. versionadded:: 3.3.0

        """
        for role in self.roles:
            if permission in role.get_permissions():
                return True
        return False

    def get_security_payload(self) -> dict[str, t.Any]:
        """Serialize user object as response payload.
        Override this to return any/all the user object in JSON responses.
        Return a dict.
        """
        return {}

    def get_redirect_qparams(
        self, existing: dict[str, t.Any] | None = None
    ) -> dict[str, t.Any]:
        """Return user info that will be added to redirect query params.

        :param existing: Existing dict of params to update.
        :return: A dict whose keys are query params and values are query values.

        The returned dict will always have an 'identity' key/value.
        If the User Model contains 'email', an 'email' key/value will be added.
        All keys provided in 'existing' will also be merged in.

        .. versionadded:: 3.2.0

        .. versionchanged:: 4.0.0
            Add 'identity' using UserMixin.calc_username() - email is optional.
        """
        if not existing:
            existing = {}
        if hasattr(self, "email"):
            existing.update({"email": self.email})
        existing.update({"identity": self.calc_username()})
        return existing

    def verify_and_update_password(self, password: str) -> bool:
        """Returns ``True`` if the password is valid for the specified user.

        Additionally, the hashed password in the database is updated if the
        hashing algorithm happens to have changed.

        N.B. you MUST call DB commit if you are using a session-based datastore
        (such as SqlAlchemy) since the user instance might have been altered
        (i.e. ``app.security.datastore.commit()``).
        This is usually handled in the view.

        :param password: A plaintext password to verify

        .. versionadded:: 3.2.0
        """
        return verify_and_update_password(password, self)

    def calc_username(self) -> str:
        """Come up with the best 'username' based on how the app
        is configured (via :py:data:`SECURITY_USER_IDENTITY_ATTRIBUTES`).
        Returns the first non-null match (and converts to string).
        In theory this should NEVER be the empty string unless the user
        record isn't actually valid.

        .. versionadded:: 3.4.0
        """
        cusername = None
        for attr in get_identity_attributes():
            cusername = getattr(self, attr, None)
            if cusername is not None and len(str(cusername)) > 0:
                break
        return str(cusername) if cusername is not None else ""

    def us_send_security_token(self, method: str, **kwargs: t.Any) -> str | None:
        """Generate and send the security code for unified sign in.

        :param method: The method in which the code will be sent
        :param kwargs: Opaque parameters that are subject to change at any time
        :return: None if successful, error message if not.

        This is a wrapper around :meth:`us_send_security_token`
        that can be overridden to manage any errors.

        .. versionadded:: 3.4.0
        """
        try:
            us_send_security_token(self, method, **kwargs)
        except Exception:
            return get_message("FAILED_TO_SEND_CODE")[0]
        return None

    def tf_send_security_token(self, method: str, **kwargs: t.Any) -> str | None:
        """Generate and send the security code for two-factor.

        :param method: The method in which the code will be sent
        :param kwargs: Opaque parameters that are subject to change at any time
        :return: None if successful, error message if not.

        This is a wrapper around :meth:`tf_send_security_token`
        that can be overridden to manage any errors.

        .. versionadded:: 3.4.0
        """
        try:
            tf_send_security_token(self, method, **kwargs)
        except Exception:
            return get_message("FAILED_TO_SEND_CODE")[0]
        return None

    def check_tf_required(
        self, tf_setup_methods: list[tuple[str, str]], tf_fresh: bool
    ) -> tuple[bool, list[tuple[str, str]]]:
        """Check if current user requires two-factor authentication.

        :param tf_setup_methods: A tuple of (two_factor method, label) - methods
            the user has already set up (from all two-factor implementations)
        :param tf_fresh: if True then user has recently completed
            two-factor authentication on the requesting device
        :return: Whether TFA is required for this user and a possibly augmented
            list of allowable methods

        The default implementation uses global configuration values.
        An application could for example require two-factor authentication for users
        with a particular role, or not require two-factor for 'new' users.
        This is called AFTER the user has successfully authenticated.

        .. versionadded:: 5.8.0
        """
        if cv("TWO_FACTOR_REQUIRED") or len(tf_setup_methods) > 0:
            if cv("TWO_FACTOR_ALWAYS_VALIDATE") or not tf_fresh:
                return True, tf_setup_methods
        return False, tf_setup_methods

    def check_tf_required_setup(self) -> bool:
        """Check if current user requires two-factor authentication.
        This is called as part of two-factor setup to inform the caller

        N.B. this is only called from tf-setup - not from webauthn and
        is only used to improve UX - the above method check_tf_required is the
        definitive answer in the authentication path.

        .. versionadded:: 5.8.0
        """
        return cv("TWO_FACTOR_REQUIRED")

    def track_failed_authn(self, auth_type: str, tfa: bool = False) -> None:
        """Called when a user fails to authenticate.

        The following flask-Security endpoints call this:

            - security.login
            - security.verify
            - security.us_signin
            - security.us_verify
            - security.us_verify_link
            - security.wan_signin_response
            - security.wan_verify_response
            - security.two_factor_token_validation

        auth_type is what failed:

            - password
            - passcode (unified signin)
            - passkey (webauthn)

        tfa - True if it was a second factor that failed

        This is called any time a credential is presented but is not verifiable.
        It is NOT called on API errors or missing data.

        Use Flask's request proxy to get information such as endpoint. Note that
        it is possible there isn't a Flask Request if this is called from the cli.

        The default implementation sends the user_failed_authn signal.

        .. versionadded:: 5.8.0
        """
        user_failed_authn.send(
            current_app._get_current_object(),  # type: ignore[attr-defined]
            _async_wrapper=current_app.ensure_sync,
            user=self,
            auth_type=auth_type,
            tfa=tfa,
        )

    def is_locked(self, form_error: list[str] | None = None) -> bool:
        """
        Return True if the user account is locked.

        It is called from the following endpoints:

            - security.login
            - security.us_signin
            - security.forgot_password
            - security.recover_username
            - security.wan_signin_response
            - oauthresponse

        For authentication endpoints it is called AFTER the credentials have been
        verified, and AFTER the check whether the user is disabled/deactivated
        but before the check for confirmation required.

        form_error is a list that could be associated with a form - used to convey
        any error messages.

        .. tip::
          This does not prevent an already authenticated user from continuing to access
          the system. Think of it similar to the confirmation sequence.
          See :meth:`.UserDatastore.deactivate_user`.

        .. versionadded:: 5.8.0
        """
        return False


class WebAuthnMixin:
    if t.TYPE_CHECKING:  # pragma: no cover
        # These are defined in the applications Model files.
        id: int
        name: str
        credential_id: bytes
        public_key: bytes
        sign_count: int
        transports: list[str] | None
        backup_state: bool
        device_type: str
        extensions: str | None
        lastuse_datetime: datetime
        usage: str

        def __init__(self, **kwargs: t.Any): ...

    def get_user_mapping(self) -> dict[str, t.Any]:
        """
        Return the filter needed by find_user() to get the user
        associated with this webauthn credential.
        Note that this probably has to be overridden when using mongoengine.

        .. versionadded:: 5.0.0
        """
        return dict(id=self.user_id)  # type: ignore


class RefreshTrackerMixin:
    if t.TYPE_CHECKING:  # pragma: no cover
        # These are defined in the application's Model files.
        id: int
        name: str
        # refresh_family and gen track rotation and lets the app react
        refresh_family: str
        gen: int
        expires_at: datetime
        revoked_at: datetime | None
        last_used_at: datetime

        def __init__(self, **kwargs: t.Any): ...
