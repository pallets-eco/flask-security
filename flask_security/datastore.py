# -*- coding: utf-8 -*-
"""
    flask_security.datastore
    ~~~~~~~~~~~~~~~~~~~~~~~~

    This module contains an user datastore classes.

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""
import json
import uuid

from .utils import config_value, get_identity_attributes, string_types


class Datastore(object):
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


class UserDatastore(object):
    """Abstracted user datastore.

    :param user_model: A user model class definition
    :param role_model: A role model class definition

    .. important::
        For mutating operations, the user/role will be added to the
        datastore (by calling self.put(<object>). If the datastore is session based
        (such as for SQLAlchemyDatastore) it is up to caller to actually
        commit the transaction by calling datastore.commit().
    """

    def __init__(self, user_model, role_model):
        self.user_model = user_model
        self.role_model = role_model

    def _prepare_role_modify_args(self, user, role):
        if isinstance(user, string_types):
            user = self.find_user(email=user)
        if isinstance(role, string_types):
            role = self.find_role(role)
        return user, role

    def _prepare_create_user_args(self, **kwargs):
        kwargs.setdefault("active", True)
        roles = kwargs.get("roles", [])
        for i, role in enumerate(roles):
            rn = role.name if isinstance(role, self.role_model) else role
            # see if the role exists
            roles[i] = self.find_role(rn)
        kwargs["roles"] = roles
        if hasattr(self.user_model, "fs_uniquifier"):
            kwargs.setdefault("fs_uniquifier", uuid.uuid4().hex)
        return kwargs

    def _is_numeric(self, value):
        try:
            int(value)
        except (TypeError, ValueError):
            return False
        return True

    def _is_uuid(self, value):
        return isinstance(value, uuid.UUID)

    def get_user(self, id_or_email):
        """Returns a user matching the specified ID or email address."""
        raise NotImplementedError

    def find_user(self, *args, **kwargs):
        """Returns a user matching the provided parameters."""
        raise NotImplementedError

    def find_role(self, *args, **kwargs):
        """Returns a role matching the provided name."""
        raise NotImplementedError

    def add_role_to_user(self, user, role):
        """Adds a role to a user.

        :param user: The user to manipulate. Can be an User object or email
        :param role: The role to add to the user. Can be a Role object or
            string role name
        """
        user, role = self._prepare_role_modify_args(user, role)
        if role not in user.roles:
            user.roles.append(role)
            self.put(user)
            return True
        return False

    def remove_role_from_user(self, user, role):
        """Removes a role from a user.

        :param user: The user to manipulate. Can be an User object or email
        :param role: The role to remove from the user. Can be a Role object or
            string role name
        """
        rv = False
        user, role = self._prepare_role_modify_args(user, role)
        if role in user.roles:
            rv = True
            user.roles.remove(role)
            self.put(user)
        return rv

    def toggle_active(self, user):
        """Toggles a user's active status. Always returns True."""
        user.active = not user.active
        self.put(user)
        return True

    def deactivate_user(self, user):
        """Deactivates a specified user. Returns `True` if a change was made.

        This will immediately disallow access to all endpoints that require
        authentication either via session or tokens.
        The user will not be able to log in again.

        :param user: The user to deactivate
        """
        if user.active:
            user.active = False
            self.put(user)
            return True
        return False

    def activate_user(self, user):
        """Activates a specified user. Returns `True` if a change was made.

        :param user: The user to activate
        """
        if not user.active:
            user.active = True
            self.put(user)
            return True
        return False

    def set_uniquifier(self, user, uniquifier=None):
        """ Set user's authentication token uniquifier.
        This will immediately render outstanding auth tokens,
        session cookies and remember cookies invalid.

        :param user: User to modify
        :param uniquifier: Unique value - if none then uuid.uuid4().hex is used

        This method is a no-op if the user model doesn't contain the attribute
        ``fs_uniquifier``

        .. versionadded:: 3.3.0
        """
        if not hasattr(user, "fs_uniquifier"):
            return
        if not uniquifier:
            uniquifier = uuid.uuid4().hex
        user.fs_uniquifier = uniquifier
        self.put(user)

    def create_role(self, **kwargs):
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
            elif isinstance(perms, string_types):
                # squash spaces.
                perms = ",".join([p.strip() for p in perms.split(",")])
            kwargs["permissions"] = perms

        role = self.role_model(**kwargs)
        return self.put(role)

    def find_or_create_role(self, name, **kwargs):
        """Returns a role matching the given name or creates it with any
        additionally provided parameters.
        """
        kwargs["name"] = name
        return self.find_role(name) or self.create_role(**kwargs)

    def create_user(self, **kwargs):
        """Creates and returns a new user from the given parameters.

        :kwparam email: required.
        :kwparam password:  Hashed password.
        :kwparam roles: list of roles to be added to user.
            Can be Role objects or strings

        .. danger::
           Be aware that whatever `password` is passed in will
           be stored directly in the DB. Do NOT pass in a plaintext password!
           Best practice is to pass in ``hash_password(plaintext_password)``.

           Furthermore, no validation is done on the password (e.g for minimum length).
           Best practice is to call
           ``app.security._password_validator(plaintext_password, True)``
           and look for a ``None`` return meaning the password conforms to the
           configured validations.

        The new user's ``active`` property will be set to ``True``
        unless explicitly set to ``False`` in `kwargs`.
        """
        kwargs = self._prepare_create_user_args(**kwargs)
        user = self.user_model(**kwargs)
        return self.put(user)

    def delete_user(self, user):
        """Deletes the specified user.

        :param user: The user to delete
        """
        self.delete(user)

    def reset_user_access(self, user):
        """
        Use this method to reset user authentication methods in the case of compromise.
        This will:

            * reset fs_uniquifier - which causes session cookie, remember cookie, auth
              tokens to be unusable
            * remove all unified signin TOTP secrets so those can't be used
            * remove all two-factor secrets so those can't be used

        Note that if using unified sign in and allow 'email' as a way to receive a code
        if the email is compromised - login is still possible. To handle this - it
        is better to deactivate the user.

        Note - this method isn't used directly by Flask-Security - it is provided
        as a helper for an applications administrative needs.

        Remember to call commit on DB if needed.

        .. versionadded:: 3.4.1
        """
        self.set_uniquifier(user)
        if hasattr(user, "us_totp_secrets"):
            self.us_reset(user)
        if hasattr(user, "tf_primary_method"):
            self.tf_reset(user)

    def tf_set(self, user, primary_method, totp_secret=None, phone=None):
        """ Set two-factor info into user record.
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
            self.put(user)

    def tf_reset(self, user):
        """ Disable two-factor auth for user

        .. versionadded: 3.4.1
        """
        user.tf_primary_method = None
        user.tf_totp_secret = None
        user.tf_phone_number = None
        self.put(user)

    def us_get_totp_secrets(self, user):
        """ Return totp secrets.
        These are json encoded in the DB.

        Returns a dict with methods as keys and secrets as values.

        .. versionadded:: 3.4.0
        """
        if not user.us_totp_secrets:
            return {}
        return json.loads(user.us_totp_secrets)

    def us_put_totp_secrets(self, user, secrets):
        """ Save secrets. Assume to be a dict (or None)
        with keys as methods, and values as (encrypted) secrets.

        .. versionadded:: 3.4.0
        """
        user.us_totp_secrets = json.dumps(secrets) if secrets else None
        self.put(user)

    def us_set(self, user, method, totp_secret=None, phone=None):
        """ Set unified sign in info into user record.

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
            self.put(user)

    def us_reset(self, user):
        """ Disable unified sign in for user.
        Be aware that if "email" is an allowed way to receive codes, they
        will still work (as totp secrets are generated on the fly).
        This will disable authenticator app and SMS.

        .. versionadded: 3.4.1
        """
        user.us_totp_secrets = None
        user.us_phone_number = None
        self.put(user)


class SQLAlchemyUserDatastore(SQLAlchemyDatastore, UserDatastore):
    """A SQLAlchemy datastore implementation for Flask-Security that assumes the
    use of the Flask-SQLAlchemy extension.
    """

    def __init__(self, db, user_model, role_model):
        SQLAlchemyDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)

    def get_user(self, identifier):
        from sqlalchemy import func as alchemyFn
        from sqlalchemy import inspect
        from sqlalchemy.sql import sqltypes
        from sqlalchemy.dialects.postgresql import UUID as PSQL_UUID

        user_model_query = self.user_model.query
        if config_value("JOIN_USER_ROLES") and hasattr(self.user_model, "roles"):
            from sqlalchemy.orm import joinedload

            user_model_query = user_model_query.options(joinedload("roles"))

        # To support both numeric, string, and UUID primary keys, and support
        # calling this routine with either a numeric value or a string or a UUID
        # we need to make sure the types basically match.
        # psycopg2 for example will complain if we attempt to 'get' a
        # numeric primary key with a string value.
        # TODO: other datastores don't support this - they assume the only
        # PK is user.id. That makes things easier but for backwards compat...
        ins = inspect(self.user_model)
        pk_type = ins.primary_key[0].type
        pk_isnumeric = isinstance(pk_type, sqltypes.Integer)
        pk_isuuid = isinstance(pk_type, PSQL_UUID)
        # Are they the same or NOT numeric nor UUID
        if (
            (pk_isnumeric and self._is_numeric(identifier))
            or (pk_isuuid and self._is_uuid(identifier))
            or (not pk_isnumeric and not pk_isuuid)
        ):
            rv = self.user_model.query.get(identifier)
            if rv is not None:
                return rv

        # Not PK - iterate through other attributes and look for 'identifier'
        for attr in get_identity_attributes():
            column = getattr(self.user_model, attr)
            attr_isnumeric = isinstance(column.type, sqltypes.Integer)

            query = None
            if attr_isnumeric and self._is_numeric(identifier):
                query = column == identifier
            elif not attr_isnumeric and not self._is_numeric(identifier):
                # Look for exact case-insensitive match - 'ilike' honors
                # wild cards which isn't what we want.
                query = alchemyFn.lower(column) == alchemyFn.lower(identifier)
            if query is not None:
                rv = user_model_query.filter(query).first()
                if rv is not None:
                    return rv

    def find_user(self, **kwargs):
        query = self.user_model.query
        if config_value("JOIN_USER_ROLES") and hasattr(self.user_model, "roles"):
            from sqlalchemy.orm import joinedload

            query = query.options(joinedload("roles"))

        return query.filter_by(**kwargs).first()

    def find_role(self, role):
        return self.role_model.query.filter_by(name=role).first()


class SQLAlchemySessionUserDatastore(SQLAlchemyUserDatastore, SQLAlchemyDatastore):
    """A SQLAlchemy datastore implementation for Flask-Security that assumes the
    use of the flask_sqlalchemy_session extension.
    """

    def __init__(self, session, user_model, role_model):
        class PretendFlaskSQLAlchemyDb(object):
            """ This is a pretend db object, so we can just pass in a session.
            """

            def __init__(self, session):
                self.session = session

        SQLAlchemyUserDatastore.__init__(
            self, PretendFlaskSQLAlchemyDb(session), user_model, role_model
        )

    def commit(self):
        super(SQLAlchemySessionUserDatastore, self).commit()


class MongoEngineUserDatastore(MongoEngineDatastore, UserDatastore):
    """A MongoEngine datastore implementation for Flask-Security that assumes
    the use of the Flask-MongoEngine extension.
    """

    def __init__(self, db, user_model, role_model):
        MongoEngineDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)

    def get_user(self, identifier):
        from mongoengine import ValidationError

        try:
            return self.user_model.objects(id=identifier).first()
        except (ValidationError, ValueError):
            pass

        is_numeric = self._is_numeric(identifier)

        for attr in get_identity_attributes():
            query_key = attr if is_numeric else "%s__iexact" % attr
            query = {query_key: identifier}
            try:
                rv = self.user_model.objects(**query).first()
                if rv is not None:
                    return rv
            except (ValidationError, ValueError):
                # This can happen if identifier is a string but attribute is
                # an int.
                pass

    def find_user(self, **kwargs):
        try:
            from mongoengine.queryset import Q, QCombination
        except ImportError:
            from mongoengine.queryset.visitor import Q, QCombination
        from mongoengine.errors import ValidationError

        queries = map(lambda i: Q(**{i[0]: i[1]}), kwargs.items())
        query = QCombination(QCombination.AND, queries)
        try:
            return self.user_model.objects(query).first()
        except ValidationError:  # pragma: no cover
            return None

    def find_role(self, role):
        return self.role_model.objects(name=role).first()


class PeeweeUserDatastore(PeeweeDatastore, UserDatastore):
    """A PeeweeD datastore implementation for Flask-Security that assumes the
    use of Peewee Flask utils.

    :param user_model: A user model class definition
    :param role_model: A role model class definition
    :param role_link: A model implementing the many-to-many user-role relation
    """

    def __init__(self, db, user_model, role_model, role_link):
        PeeweeDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)
        self.UserRole = role_link

    def get_user(self, identifier):
        from peewee import fn as peeweeFn
        from peewee import IntegerField

        # For peewee we only (currently) support numeric primary keys.
        if self._is_numeric(identifier):
            try:
                return self.user_model.get(self.user_model.id == identifier)
            except (self.user_model.DoesNotExist, ValueError):
                pass

        for attr in get_identity_attributes():
            # Read above (SQLAlchemy store) for why we are checking types.
            column = getattr(self.user_model, attr)
            attr_isnumeric = isinstance(column, IntegerField)
            try:
                if attr_isnumeric and self._is_numeric(identifier):
                    return self.user_model.get(column == identifier)
                elif not attr_isnumeric and not self._is_numeric(identifier):
                    return self.user_model.get(
                        peeweeFn.Lower(column) == peeweeFn.Lower(identifier)
                    )
            except (self.user_model.DoesNotExist, ValueError):
                pass

    def find_user(self, **kwargs):
        try:
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
        user, role = self._prepare_role_modify_args(user, role)
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
        user, role = self._prepare_role_modify_args(user, role)
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
    """A Pony ORM datastore implementation for Flask-Security.

    Code primarily from https://github.com/ET-CS but taken over after
    being abandoned.
    """

    def __init__(self, db, user_model, role_model):
        PonyDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)

    @with_pony_session
    def get_user(self, identifier):
        from pony.orm.core import ObjectNotFound

        try:
            return self.user_model[identifier]
        except (ObjectNotFound, ValueError):
            pass

        for attr in get_identity_attributes():
            # this is a nightmare, tl;dr we need to get the thing that
            # corresponds to email (usually)
            try:
                user = self.user_model.get(**{attr: identifier})
                if user is not None:
                    return user
            except (TypeError, ValueError):
                pass

    @with_pony_session
    def find_user(self, **kwargs):
        return self.user_model.get(**kwargs)

    @with_pony_session
    def find_role(self, role):
        return self.role_model.get(name=role)

    @with_pony_session
    def add_role_to_user(self, *args, **kwargs):
        return super(PonyUserDatastore, self).add_role_to_user(*args, **kwargs)

    @with_pony_session
    def create_user(self, **kwargs):
        return super(PonyUserDatastore, self).create_user(**kwargs)

    @with_pony_session
    def create_role(self, **kwargs):
        return super(PonyUserDatastore, self).create_role(**kwargs)
