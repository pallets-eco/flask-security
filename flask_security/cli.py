"""
    flask_security.cli
    ~~~~~~~~~~~~~~~~~~

    Command Line Interface for managing accounts and roles.

    :copyright: (c) 2016 by CERN.
    :copyright: (c) 2019-2020 by J. Christopher Wagner
    :license: MIT, see LICENSE for more details.
"""


from functools import wraps

import click
from flask import current_app
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy
from .quart_compat import get_quart_status

from .utils import (
    find_user,
    get_identity_attributes,
    get_identity_attribute,
    hash_password,
)

if get_quart_status():  # pragma: no cover
    import quart.cli
    import functools

    # quart cli doesn't provide the with_appcontext function
    def with_appcontext(f):
        """Wraps a callback so that it's guaranteed to be executed with the
        script's application context.  If callbacks are registered directly
        to the ``app.cli`` object then they are wrapped with this function
        by default unless it's disabled.
        """

        @click.pass_context
        def decorator(__ctx, *args, **kwargs):
            with __ctx.ensure_object(quart.cli.ScriptInfo).load_app().app_context():
                return __ctx.invoke(f, *args, **kwargs)

        return functools.update_wrapper(decorator, f)


else:
    import flask.cli

    with_appcontext = flask.cli.with_appcontext


_security = LocalProxy(lambda: current_app.extensions["security"])
_datastore = LocalProxy(lambda: current_app.extensions["security"].datastore)


def commit(fn):
    """Decorator to commit changes in datastore."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        fn(*args, **kwargs)
        _datastore.commit()

    return wrapper


def fix_errors(form_errors):
    # Form errors might have lazy text which normally would be processed by
    # render_template
    errors = {}
    for k, v in form_errors.items():
        errors[k] = [str(e) for e in v]
    return errors


@click.group()
def users():
    """User commands.

    For commands that require a USER - pass in any identity attribute.
    """


@click.group()
def roles():
    """Role commands."""


@users.command(
    "create",
    help="Create a new user with one or more attributes using the syntax:"
    " attr:value. If attr isn't set 'email' is presumed."
    " Identity attribute values will be validated using the configured"
    " confirm_register_form;"
    " however, any ADDITIONAL attribute:value pairs will be sent to"
    " datastore.create_user",
)
@click.argument(
    "attributes",
    nargs=-1,
)
@click.password_option()
@click.option("-a", "--active", default=False, is_flag=True)
@with_appcontext
@commit
def users_create(attributes, password, active):
    """Create a user."""
    kwargs = {}

    identity_attributes = get_identity_attributes()
    for attrarg in attributes:
        # If given identity is an identity_attribute - do a bit of pre-validating
        # to provide nicer errors.
        attr = "email"
        if ":" in attrarg:
            attr, attrarg = attrarg.split(":")
        if attr in identity_attributes:
            details = get_identity_attribute(attr)
            idata = details["mapper"](attrarg)
            if not idata:
                raise click.UsageError(
                    f"Attr {attr} with value {attrarg} wasn't accepted by mapper"
                )

        kwargs[attr] = attrarg
    kwargs.update(**{"password": password})

    form = _security.confirm_register_form(MultiDict(kwargs), meta={"csrf": False})

    if form.validate():
        # We don't use the form directly to provide values so that this CLI can actually
        # set any usermodel attribute. We do grab email and password from the form
        # so that we get any normalization results.
        kwargs["password"] = hash_password(form.password.data)
        kwargs["active"] = active
        # echo normalized email...
        if "email" in kwargs:
            kwargs["email"] = form.email.data
        _datastore.create_user(**kwargs)
        click.secho("User created successfully.", fg="green")
        kwargs["password"] = "****"
        click.echo(kwargs)
    else:
        raise click.UsageError("Error creating user. %s" % fix_errors(form.errors))


@roles.command("create")
@click.argument("name")
@click.option("-d", "--description", default=None)
@click.option("-p", "--permissions", help="A comma separated list")
@with_appcontext
@commit
def roles_create(**kwargs):
    """Create a role."""

    # For some reason Click puts arguments in kwargs - even if they weren't specified.
    if "permissions" in kwargs and not kwargs["permissions"]:
        del kwargs["permissions"]
    if "permissions" in kwargs and not hasattr(_datastore.role_model, "permissions"):
        raise click.UsageError("Role model does not support permissions")
    _datastore.create_role(**kwargs)
    click.secho('Role "%(name)s" created successfully.' % kwargs, fg="green")


@roles.command("add")
@click.argument("user")
@click.argument("role")
@with_appcontext
@commit
def roles_add(user, role):
    """Add user to role."""
    user_obj = find_user(user)
    if user_obj is None:
        raise click.UsageError("User not found.")

    role = _datastore._prepare_role_modify_args(role)
    if role is None:
        raise click.UsageError("Cannot find role.")
    if _datastore.add_role_to_user(user_obj, role):
        click.secho(
            f'Role "{role.name}" added to user "{user}" successfully.',
            fg="green",
        )
    else:
        raise click.UsageError("Cannot add role to user.")


@roles.command("remove")
@click.argument("user")
@click.argument("role")
@with_appcontext
@commit
def roles_remove(user, role):
    """Remove user from role."""
    user_obj = find_user(user)
    if user_obj is None:
        raise click.UsageError("User not found.")

    role = _datastore._prepare_role_modify_args(role)
    if role is None:
        raise click.UsageError("Cannot find role.")
    if _datastore.remove_role_from_user(user_obj, role):
        click.secho(
            f'Role "{role.name}" removed from user "{user}" successfully.',
            fg="green",
        )
    else:
        raise click.UsageError("Cannot remove role from user.")


@roles.command("add_permissions")
@click.argument("role")
@click.argument("permissions")
@with_appcontext
@commit
def roles_add_permissions(role, permissions):
    """Add permissions to role.

    Role is an existing role name.
    Permissions are a comma separated list.
    """
    role = _datastore._prepare_role_modify_args(role)
    if role is None:
        raise click.UsageError("Cannot find role.")
    if _datastore.add_permissions_to_role(role, permissions):
        click.secho(
            f'Permission(s) "{permissions}" added to role "{role.name}" successfully.',
            fg="green",
        )
    else:  # pragma: no cover
        raise click.UsageError("Cannot add permission(s) to role.")


@roles.command("remove_permissions")
@click.argument("role")
@click.argument("permissions")
@with_appcontext
@commit
def roles_remove_permissions(role, permissions):
    """Remove permissions from role.

    Role is an existing role name.
    Permissions are a comma separated list.
    """
    role = _datastore._prepare_role_modify_args(role)
    if role is None:
        raise click.UsageError("Cannot find role.")
    if _datastore.remove_permissions_from_role(role, permissions):
        click.secho(
            f'Permission(s) "{permissions}" removed from role'
            f' "{role.name}" successfully.',
            fg="green",
        )
    else:  # pragma: no cover
        raise click.UsageError("Cannot remove permission(s) from role.")


@users.command("activate")
@click.argument("user")
@with_appcontext
@commit
def users_activate(user):
    """Activate a user."""
    user_obj = find_user(user)
    if user_obj is None:
        raise click.UsageError("User not found.")
    if _datastore.activate_user(user_obj):
        click.secho(f'User "{user}" has been activated.', fg="green")
    else:
        click.secho(f'User "{user}" was already activated.', fg="yellow")


@users.command("deactivate")
@click.argument("user")
@with_appcontext
@commit
def users_deactivate(user):
    """Deactivate a user."""
    user_obj = find_user(user)
    if user_obj is None:
        raise click.UsageError("User not found.")
    if _datastore.deactivate_user(user_obj):
        click.secho(f'User "{user}" has been deactivated.', fg="green")
    else:
        click.secho(f'User "{user}" was already deactivated.', fg="yellow")


@users.command(
    "reset_access",
    help="Reset all authentication credentials for user."
    " This includes sessions, authentication tokens, two-factor"
    " and unified sign in secrets. ",
)
@click.argument("user")
@with_appcontext
@commit
def users_reset_access(user):
    """ Reset all authentication tokens etc."""
    user_obj = find_user(user)
    if user_obj is None:
        raise click.UsageError("User not found.")
    _datastore.reset_user_access(user_obj)
    click.secho(
        f'User "{user}" authentication credentials have been reset.', fg="green"
    )
