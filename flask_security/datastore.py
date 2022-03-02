"""
    flask_security.datastore
    ~~~~~~~~~~~~~~~~~~~~~~~~

    This module contains an user datastore classes.

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2021 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""
import datetime
import json
import typing as t
import uuid

from .utils import config_value

if t.TYPE_CHECKING:  # pragma: no cover
    import flask_sqlalchemy
    import flask_mongoengine
    import sqlalchemy.orm.scoping


class Datastore:
    def __init__(self, db):
        self.db = db

    def commit(self):
        pass

    def put(self, model):
        raise NotImplementedError

    def delete(self, model):
        raise NotImplementedError


class SQLAlchemyDatastore(Datastore):
    def commit(self):
        self.db.session.commit()

    def put(self, model):
        self.db.session.add(model)
        return model

    def delete(self, model):
        self.db.session.delete(model)


class MongoEngineDatastore(Datastore):
    def put(self, model):
        model.save()
        return model

    def delete(self, model):
        model.delete()


class PeeweeDatastore(Datastore):
    def put(self, model):
        model.save()
        return model

    def delete(self, model):
        model.delete_instance(recursive=True)


def with_pony_session(f):
    from functools import wraps

    @wraps(f)
    def decorator(*args, **kwargs):
        from pony.orm import db_session
        from pony.orm.core import local
        from flask import (
            after_this_request,
            current_app,
            has_app_context,
            has_request_context,
        )
        from flask.signals import appcontext_popped

        register = local.db_context_counter == 0
        if register and (has_app_context() or has_request_context()):
            db_session.__enter__()

        result = f(*args, **kwargs)

        if register:
            if has_request_context():

                @after_this_request
                def pop(request):
                    db_session.__exit__()
                    return request

            elif has_app_context():

                @appcontext_popped.connect_via(current_app._get_current_object())
                def pop(sender, *args, **kwargs):
                    while local.db_context_counter:
                        db_session.__exit__()

            else:
                raise RuntimeError("Needs app or request context")
        return result

    return decorator


class PonyDatastore(Datastore):
    def commit(self):
        self.db.commit()

    @with_pony_session
    def put(self, model):
        return model

    @with_pony_session
    def delete(self, model):
        model.delete()


class UserDatastore:
    """Abstracted user datastore.

    :param user_model: A user model class definition
    :param role_model: A role model class definition

    .. important::
        For mutating operations, the user/role will be added to the
        datastore (by calling self.put(<object>). If the datastore is session based
        (such as for SQLAlchemyDatastore) it is up to caller to actually
        commit the transaction by calling datastore.commit().
    """

    def __init__(self, user_model: t.Type["User"], role_model: t.Type["Role"]):
        self.user_model = user_model
        self.role_model = role_model

    def _prepare_role_modify_args(
        self, role: t.Union[str, "Role"]
    ) -> t.Union["Role", None]:
        if isinstance(role, str):
            return self.find_role(role)
        return role

    def _prepare_create_user_args(self, **kwargs):
        kwargs.setdefault("active", True)
        roles = kwargs.get("roles", [])
        for i, role in enumerate(roles):
            rn = role.name if isinstance(role, self.role_model) else role
            # see if the role exists
            roles[i] = self.find_role(rn)
        kwargs["roles"] = roles
        kwargs.setdefault("fs_uniquifier", uuid.uuid4().hex)
        if hasattr(self.user_model, "fs_token_uniquifier"):
            kwargs.setdefault("fs_token_uniquifier", uuid.uuid4().hex)

        return kwargs

    def find_user(
        self, case_insensitive: bool = False, **kwargs: t.Any
    ) -> t.Union["User", None]:
        """Returns a user matching the provided parameters."""
        raise NotImplementedError

    def find_role(self, role: str) -> t.Union["Role", None]:
        """Returns a role matching the provided name."""
        raise NotImplementedError

    def add_role_to_user(self, user: "User", role: t.Union["Role", str]) -> bool:
        """Adds a role to a user.

        :param user: The user to manipulate.
        :param role: The role to add to the user. Can be a Role object or
            string role name
        :return: True is role was added, False if role already existed.
        """
        role_obj = self._prepare_role_modify_args(role)
        if not role_obj:
            raise ValueError(f"Role: {role} doesn't exist")
        if role_obj not in user.roles:
            user.roles.append(role_obj)
            self.put(user)  # type: ignore
            return True
        return False

    def remove_role_from_user(self, user: "User", role: t.Union["Role", str]) -> bool:
        """Removes a role from a user.

        :param user: The user to manipulate. Can be an User object or email
        :param role: The role to remove from the user. Can be a Role object or
            string role name
        :return: True if role was removed, False if role doesn't exist or user didn't
            have role.
        """
        rv = False
        role_obj = self._prepare_role_modify_args(role)
        if role_obj in user.roles:
            rv = True
            user.roles.remove(role_obj)
            self.put(user)  # type: ignore
        return rv

    def add_permissions_to_role(
        self, role: t.Union["Role", str], permissions: t.Union[set, list, str]
    ) -> bool:
        """Add one or more permissions to role.

        :param role: The role to modify. Can be a Role object or
            string role name
        :param permissions: a set, list, or single string.
        :return: True if permissions added, False if role doesn't exist.

        Caller must commit to DB.

        .. versionadded:: 4.0.0
        """

        rv = False
        role_obj = self._prepare_role_modify_args(role)
        if role_obj:
            rv = True
            role_obj.add_permissions(permissions)
            self.put(role_obj)  # type: ignore
        return rv

    def remove_permissions_from_role(
        self, role: t.Union["Role", str], permissions: t.Union[set, list, str]
    ) -> bool:
        """Remove one or more permissions from a role.

        :param role: The role to modify. Can be a Role object or
            string role name
        :param permissions: a set, list, or single string.
        :return: True if permissions removed, False if role doesn't exist.

        Caller must commit to DB.

        .. versionadded:: 4.0.0
        """

        rv = False
        role_obj = self._prepare_role_modify_args(role)
        if role_obj:
            rv = True
            role_obj.remove_permissions(permissions)
            self.put(role_obj)  # type: ignore
        return rv

    def toggle_active(self, user: "User") -> bool:
        """Toggles a user's active status. Always returns True."""
        user.active = not user.active
        self.put(user)  # type: ignore
        return True

    def deactivate_user(self, user: "User") -> bool:
        """Deactivates a specified user. Returns `True` if a change was made.

        This will immediately disallow access to all endpoints that require
        authentication either via session or tokens.
        The user will not be able to log in again.

        :param user: The user to deactivate
        """
        if user.active:
            user.active = False
            self.put(user)  # type: ignore
            return True
        return False

    def activate_user(self, user: "User") -> bool:
        """Activates a specified user. Returns `True` if a change was made.

        :param user: The user to activate
        """
        if not user.active:
            user.active = True
            self.put(user)  # type: ignore
            return True
        return False

    def set_uniquifier(
        self, user: "User", uniquifier: t.Union[str, None] = None
    ) -> None:
        """Set user's Flask-Security identity key.
        This will immediately render outstanding auth tokens,
        session cookies and remember cookies invalid.

        :param user: User to modify
        :param uniquifier: Unique value - if none then uuid.uuid4().hex is used

        .. versionadded:: 3.3.0
        """
        if not uniquifier:
            uniquifier = uuid.uuid4().hex
        user.fs_uniquifier = uniquifier
        self.put(user)  # type: ignore

    def set_token_uniquifier(
        self, user: "User", uniquifier: t.Union[str, None] = None
    ) -> None:
        """Set user's auth token identity key.
        This will immediately render outstanding auth tokens invalid.

        :param user: User to modify
        :param uniquifier: Unique value - if none then uuid.uuid4().hex is used

        This method is a no-op if the user model doesn't contain the attribute
        ``fs_token_uniquifier``

        .. versionadded:: 4.0.0
        """
        if not uniquifier:
            uniquifier = uuid.uuid4().hex
        if hasattr(user, "fs_token_uniquifier"):
            user.fs_token_uniquifier = uniquifier
            self.put(user)  # type: ignore

    def create_role(self, **kwargs: t.Any) -> "Role":
        """
        Creates and returns a new role from the given parameters.
        Supported params (depending on RoleModel):

        :kwparam name: Role name
        :kwparam permissions: a comma delimited list of permissions, a set or a list.
            These are user-defined strings that correspond to strings used with
            @permissions_required()

            .. versionadded:: 3.3.0

        """

        # By default we just use raw DB model create - for permissions we want to
        # be nicer and allow sending in a list or set or comma separated string.
        if "permissions" in kwargs and hasattr(self.role_model, "permissions"):
            perms = kwargs["permissions"]
            if isinstance(perms, list) or isinstance(perms, set):
                perms = ",".join(perms)
            elif isinstance(perms, str):
                # squash spaces.
                perms = ",".join(p.strip() for p in perms.split(","))
            kwargs["permissions"] = perms

        role = self.role_model(**kwargs)
        return self.put(role)  # type: ignore

    def find_or_create_role(self, name: str, **kwargs: t.Any) -> "Role":
        """Returns a role matching the given name or creates it with any
        additionally provided parameters.
        """
        return self.find_role(name) or self.create_role(name=name, **kwargs)

    def create_user(self, **kwargs: t.Any) -> "User":
        """Creates and returns a new user from the given parameters.

        :kwparam email: required.
        :kwparam password:  Hashed password.
        :kwparam roles: list of roles to be added to user.
            Can be Role objects or strings

        Any other element of the User data model may be supplied as well.

        .. note::
            No normalization is done on email - it is assumed the caller has already
            done that.

            Best practice is::

                try:
                    enorm = app.security._mail_util.validate(email)
                except ValueError:

        .. note::
            The roles kwparam is modified as part of the call - it will, if necessary
            be converted from names to role instances.

        .. danger::
           Be aware that whatever `password` is passed in will
           be stored directly in the DB. Do NOT pass in a plaintext password!
           Best practice is to pass in ``hash_password(plaintext_password)``.

           Furthermore, no validation nor normalization is done on the password
           (e.g for minimum length).

           Best practice is::

            pbad, pnorm = app.security._password_util.validate(password, True)

           Look for `pbad` being None. Pass the normalized password `pnorm` to this
           method.

        The new user's ``active`` property will be set to ``True``
        unless explicitly set to ``False`` in `kwargs` (e.g. active = False)
        """
        kwargs = self._prepare_create_user_args(**kwargs)
        user = self.user_model(**kwargs)
        return self.put(user)  # type: ignore

    def delete_user(self, user: "User") -> None:
        """Deletes the specified user.

        :param user: The user to delete
        """
        self.delete(user)  # type: ignore

    def reset_user_access(self, user: "User") -> None:
        """
        Use this method to reset user authentication methods in the case of compromise.
        This will:

            * reset fs_uniquifier - which causes session cookie, remember cookie, auth
              tokens to be unusable
            * reset fs_token_uniquifier (if present) - cause auth tokens to be unusable
            * remove all unified signin TOTP secrets so those can't be used
            * remove all two-factor secrets so those can't be used

        Note that if using unified sign in and allow 'email' as a way to receive a code;
        if the email is compromised - login is still possible. To handle this - it
        is better to deactivate the user.

        Note - this method isn't used directly by Flask-Security - it is provided
        as a helper for an application's administrative needs.

        Remember to call commit on DB if needed.

        .. versionadded:: 3.4.1
        """
        self.set_uniquifier(user)
        self.set_token_uniquifier(user)
        if hasattr(user, "us_totp_secrets"):
            self.us_reset(user)
        if hasattr(user, "tf_primary_method"):
            self.tf_reset(user)

    def tf_set(
        self,
        user: "User",
        primary_method: str,
        totp_secret: t.Optional[str] = None,
        phone: t.Optional[str] = None,
    ) -> None:
        """Set two-factor info into user record.
        This carefully only changes things if different.

        If totp_secret isn't provided - existing one won't be changed.
        If phone isn't provided, the existing phone number won't be changed.

        This could be called from an application to apiori setup a user for two factor
        without the user having to go through the setup process.

        To get a totp_secret - use ``app.security._totp_factory.generate_totp_secret()``

        .. versionadded: 3.4.1
        """

        changed = False
        if user.tf_primary_method != primary_method:
            user.tf_primary_method = primary_method
            changed = True
        if totp_secret and user.tf_totp_secret != totp_secret:
            user.tf_totp_secret = totp_secret
            changed = True
        if phone and user.tf_phone_number != phone:
            user.tf_phone_number = phone
            changed = True
        if changed:
            self.put(user)  # type: ignore

    def tf_reset(self, user: "User") -> None:
        """Disable two-factor auth for user

        .. versionadded: 3.4.1
        """
        user.tf_primary_method = None
        user.tf_totp_secret = None
        user.tf_phone_number = None
        self.put(user)  # type: ignore

    def us_get_totp_secrets(self, user: "User") -> t.Dict[str, str]:
        """Return totp secrets.
        These are json encoded in the DB.

        Returns a dict with methods as keys and secrets as values.

        .. versionadded:: 3.4.0
        """
        if not user.us_totp_secrets:
            return {}
        return json.loads(user.us_totp_secrets)

    def us_put_totp_secrets(
        self, user: "User", secrets: t.Optional[t.Dict[str, str]]
    ) -> None:
        """Save secrets. Assume to be a dict (or None)
        with keys as methods, and values as (encrypted) secrets.

        .. versionadded:: 3.4.0
        """
        user.us_totp_secrets = json.dumps(secrets) if secrets else None
        self.put(user)  # type: ignore

    def us_set(
        self,
        user: "User",
        method: str,
        totp_secret: t.Optional[str] = None,
        phone: t.Optional[str] = None,
    ) -> None:
        """Set unified sign in info into user record.

        If totp_secret isn't provided - existing one won't be changed.
        If phone isn't provided, the existing phone number won't be changed.

        This could be called from an application to apiori setup a user for unified
        sign in without the user having to go through the setup process.

        To get a totp_secret - use ``app.security._totp_factory.generate_totp_secret()``

        .. versionadded: 3.4.1
        """

        if totp_secret:
            totp_secrets = self.us_get_totp_secrets(user)
            totp_secrets[method] = totp_secret
            self.us_put_totp_secrets(user, totp_secrets)
        if phone and user.us_phone_number != phone:
            user.us_phone_number = phone
            self.put(user)  # type: ignore

    def us_reset(self, user: "User") -> None:
        """Disable unified sign in for user.
        Be aware that if "email" is an allowed way to receive codes, they
        will still work (as totp secrets are generated on the fly).
        This will disable authenticator app and SMS.

        .. versionadded: 3.4.1
        """
        user.us_totp_secrets = None
        self.put(user)  # type: ignore


class SQLAlchemyUserDatastore(SQLAlchemyDatastore, UserDatastore):
    """A UserDatastore implementation that assumes the
    use of
    `Flask-SQLAlchemy <https://pypi.python.org/pypi/flask-sqlalchemy/>`_
    for datastore transactions.

    :param db:
    :param user_model: See :ref:`Models <models_topic>`.
    :param role_model: See :ref:`Models <models_topic>`.
    """

    def __init__(
        self,
        db: "flask_sqlalchemy.SQLAlchemy",
        user_model: t.Type["User"],
        role_model: t.Type["Role"],
    ):
        SQLAlchemyDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)

    def find_user(
        self, case_insensitive: bool = False, **kwargs: t.Any
    ) -> t.Union["User", None]:
        from sqlalchemy import func as alchemyFn

        query = self.user_model.query
        if config_value("JOIN_USER_ROLES") and hasattr(self.user_model, "roles"):
            from sqlalchemy.orm import joinedload

            query = query.options(joinedload(self.user_model.roles))

        if case_insensitive:
            # While it is of course possible to pass in multiple keys to filter on
            # that isn't the normal use case. If caller asks for case_insensitive
            # AND gives multiple keys - throw an error.
            if len(kwargs) > 1:
                raise ValueError("Case insensitive option only supports single key")
            attr, identifier = kwargs.popitem()
            subquery = alchemyFn.lower(
                getattr(self.user_model, attr)
            ) == alchemyFn.lower(identifier)
            return query.filter(subquery).first()
        else:
            return query.filter_by(**kwargs).first()

    def find_role(self, role: str) -> t.Union["Role", None]:
        return self.role_model.query.filter_by(name=role).first()  # type: ignore


class SQLAlchemySessionUserDatastore(SQLAlchemyUserDatastore, SQLAlchemyDatastore):
    """A UserDatastore implementation that directly uses
    `SQLAlchemy's <https://docs.sqlalchemy.org/en/14/orm/session_basics.html>`_
    session API.

    :param session:
    :param user_model: See :ref:`Models <models_topic>`.
    :param role_model: See :ref:`Models <models_topic>`.
    """

    def __init__(
        self,
        session: "sqlalchemy.orm.scoping.scoped_session",
        user_model: t.Type["User"],
        role_model: t.Type["Role"],
    ):
        class PretendFlaskSQLAlchemyDb:
            """This is a pretend db object, so we can just pass in a session."""

            def __init__(self, session):
                self.session = session

        SQLAlchemyUserDatastore.__init__(
            self, PretendFlaskSQLAlchemyDb(session), user_model, role_model
        )

    def commit(self):
        super().commit()


class MongoEngineUserDatastore(MongoEngineDatastore, UserDatastore):
    """A UserDatastore implementation that assumes the
    use of
    `Flask-MongoEngine <https://pypi.python.org/pypi/flask-mongoengine/>`_
    for datastore transactions.

    :param db:
    :param user_model: See :ref:`Models <models_topic>`.
    :param role_model: See :ref:`Models <models_topic>`.
    """

    def __init__(
        self,
        db: "flask_mongoengine.MongoEngine",
        user_model: t.Type["User"],
        role_model: t.Type["Role"],
    ):
        MongoEngineDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)

    def find_user(self, case_insensitive=False, **kwargs):
        from mongoengine.queryset.visitor import Q, QCombination
        from mongoengine.errors import ValidationError

        try:
            if case_insensitive:
                # While it is of course possible to pass in multiple keys to filter on
                # that isn't the normal use case. If caller asks for case_insensitive
                # AND gives multiple keys - throw an error.
                if len(kwargs) > 1:
                    raise ValueError("Case insensitive option only supports single key")
                attr, identifier = kwargs.popitem()
                query = {f"{attr}__iexact": identifier}
                return self.user_model.objects(**query).first()
            else:
                queries = map(lambda i: Q(**{i[0]: i[1]}), kwargs.items())
                query = QCombination(QCombination.AND, queries)
                return self.user_model.objects(query).first()
        except ValidationError:  # pragma: no cover
            return None

    def find_role(self, role):
        return self.role_model.objects(name=role).first()


class PeeweeUserDatastore(PeeweeDatastore, UserDatastore):
    """A UserDatastore implementation that assumes the
    use of
    `Peewee Flask utils \
       <https://docs.peewee-orm.com/en/latest/peewee/playhouse.html#flask-utils>`_
    for datastore transactions.

    :param db:
    :param user_model: See :ref:`Models <models_topic>`.
    :param role_model: See :ref:`Models <models_topic>`.
    :param role_link:
    """

    def __init__(self, db, user_model, role_model, role_link):
        """
        :param db:
        :param user_model: A user model class definition
        :param role_model: A role model class definition
        :param role_link: A model implementing the many-to-many user-role relation
        """
        PeeweeDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)
        self.UserRole = role_link

    def find_user(self, case_insensitive=False, **kwargs):
        from peewee import fn as peeweeFn

        try:
            if case_insensitive:
                # While it is of course possible to pass in multiple keys to filter on
                # that isn't the normal use case. If caller asks for case_insensitive
                # AND gives multiple keys - throw an error.
                if len(kwargs) > 1:
                    raise ValueError("Case insensitive option only supports single key")
                attr, identifier = kwargs.popitem()
                return self.user_model.get(
                    peeweeFn.lower(getattr(self.user_model, attr))
                    == peeweeFn.lower(identifier)
                )
            else:
                return self.user_model.filter(**kwargs).get()
        except self.user_model.DoesNotExist:
            return None

    def find_role(self, role):
        try:
            return self.role_model.filter(name=role).get()
        except self.role_model.DoesNotExist:
            return None

    def create_user(self, **kwargs):
        """Creates and returns a new user from the given parameters."""
        roles = kwargs.pop("roles", [])
        user = self.user_model(**self._prepare_create_user_args(**kwargs))
        user = self.put(user)
        for role in roles:
            self.add_role_to_user(user, role)
        self.put(user)
        return user

    def add_role_to_user(self, user, role):
        """Adds a role to a user.

        :param user: The user to manipulate
        :param role: The role to add to the user
        """
        role = self._prepare_role_modify_args(role)
        result = self.UserRole.select().where(
            self.UserRole.user == user.id, self.UserRole.role == role.id
        )
        if result.count():
            return False
        else:
            self.put(self.UserRole.create(user=user.id, role=role.id))
            return True

    def remove_role_from_user(self, user, role):
        """Removes a role from a user.

        :param user: The user to manipulate
        :param role: The role to remove from the user
        """
        role = self._prepare_role_modify_args(role)
        result = self.UserRole.select().where(
            self.UserRole.user == user, self.UserRole.role == role
        )
        if result.count():
            query = self.UserRole.delete().where(
                self.UserRole.user == user, self.UserRole.role == role
            )
            query.execute()
            return True
        else:
            return False


class PonyUserDatastore(PonyDatastore, UserDatastore):
    """A UserDatastore implementation that assumes the
    use of
    `PonyORM <https://pypi.python.org/pypi/pony/>`_
    for datastore transactions.

    Code primarily from https://github.com/ET-CS but taken over after
    being abandoned.

    :param db:
    :param user_model: See :ref:`Models <models_topic>`.
    :param role_model: See :ref:`Models <models_topic>`.
    """

    def __init__(self, db, user_model, role_model):
        PonyDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)

    @with_pony_session
    def find_user(self, case_insensitive=False, **kwargs):
        if case_insensitive:
            # While it is of course possible to pass in multiple keys to filter on
            # that isn't the normal use case. If caller asks for case_insensitive
            # AND gives multiple keys - throw an error.
            if len(kwargs) > 1:
                raise ValueError("Case insensitive option only supports single key")
            # TODO - implement case insensitive look ups.

        return self.user_model.get(**kwargs)

    @with_pony_session
    def find_role(self, role):
        return self.role_model.get(name=role)

    @with_pony_session
    def add_role_to_user(self, *args, **kwargs):
        return super().add_role_to_user(*args, **kwargs)

    @with_pony_session
    def create_user(self, **kwargs):
        return super().create_user(**kwargs)

    @with_pony_session
    def create_role(self, **kwargs):
        return super().create_role(**kwargs)


if t.TYPE_CHECKING:  # pragma: no cover
    # Normally - the application creates the Models and glues them together
    # For typing we do that here since we don't know which DB interface they
    # will pick.
    from .core import UserMixin, RoleMixin

    class CanonicalUserDatastore(Datastore, UserDatastore):
        pass

    class User(UserMixin):
        id: int
        email: str
        username: t.Optional[str]
        password: str
        active: bool
        fs_uniquifier: str
        fs_token_uniquifier: str
        confirmed_at: datetime.datetime
        last_login_at: datetime.datetime
        current_login_at: datetime.datetime
        last_login_ip: t.Optional[str]
        current_login_ip: t.Optional[str]
        login_count: int
        tf_primary_method: t.Optional[str]
        tf_totp_secret: t.Optional[str]
        tf_phone_number: t.Optional[str]
        us_phone_number: t.Optional[str]
        us_totp_secrets: t.Optional[t.Union[str, bytes]]
        create_datetime: datetime.datetime
        update_datetime: datetime.datetime
        roles: t.List["Role"]

        def __init__(self, **kwargs):
            ...

    class Role(RoleMixin):
        id: int
        name: str
        description: t.Optional[str]
        permissions: t.Optional[t.Union[str, set, list]]
        update_datetime: datetime.datetime

        def __init__(self, **kwargs):
            ...
