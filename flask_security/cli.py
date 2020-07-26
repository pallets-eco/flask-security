# -*- coding: utf-8 -*-
"""
    flask_security.cli
    ~~~~~~~~~~~~~~~~~~

    Command Line Interface for managing accounts and roles.

    :copyright: (c) 2016 by CERN.
    :copyright: (c) 2019 by J. Christopher Wagner
    :license: MIT, see LICENSE for more details.
"""

from __future__ import absolute_import, print_function

from functools import wraps

import click
from flask import current_app
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy
from .quart_compat import get_quart_status

from .utils import hash_password

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


@click.group()
def users():
    """User commands."""


@click.group()
def roles():
    """Role commands."""


@users.command("create")
@click.argument("identity")
@click.password_option()
@click.option("-a", "--active", default=False, is_flag=True)
@with_appcontext
@commit
def users_create(identity, password, active):
    """Create a user."""
    kwargs = {attr: identity for attr in _security.user_identity_attributes}
    kwargs.update(**{"password": password})

    form = _security.confirm_register_form(MultiDict(kwargs), meta={"csrf": False})

    if form.validate():
        kwargs["password"] = hash_password(kwargs["password"])
        kwargs["active"] = active
        _datastore.create_user(**kwargs)
        click.secho("User created successfully.", fg="green")
        kwargs["password"] = "****"
        click.echo(kwargs)
    else:
        raise click.UsageError("Error creating user. %s" % form.errors)


@roles.command("create")
@click.argument("name")
@click.option("-d", "--description", default=None)
@click.option("-p", "--permissions")
@with_appcontext
@commit
def roles_create(**kwargs):
    """Create a role."""

    # For some reaosn Click puts arguments in kwargs - even if they weren't specified.
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
    """Add role to user."""
    user, role = _datastore._prepare_role_modify_args(user, role)
    if user is None:
        raise click.UsageError("Cannot find user.")
    if role is None:
        raise click.UsageError("Cannot find role.")
    if _datastore.add_role_to_user(user, role):
        click.secho(
            'Role "{0}" added to user "{1}" ' "successfully.".format(role.name, user),
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
    """Remove role from user."""
    user, role = _datastore._prepare_role_modify_args(user, role)
    if user is None:
        raise click.UsageError("Cannot find user.")
    if role is None:
        raise click.UsageError("Cannot find role.")
    if _datastore.remove_role_from_user(user, role):
        click.secho(
            'Role "{0}" removed from user "{1}" '
            "successfully.".format(role.name, user),
            fg="green",
        )
    else:
        raise click.UsageError("Cannot remove role from user.")


@users.command("activate")
@click.argument("user")
@with_appcontext
@commit
def users_activate(user):
    """Activate a user."""
    user_obj = _datastore.get_user(user)
    if user_obj is None:
        raise click.UsageError("User not found.")
    if _datastore.activate_user(user_obj):
        click.secho('User "{0}" has been activated.'.format(user), fg="green")
    else:
        click.secho('User "{0}" was already activated.'.format(user), fg="yellow")


@users.command("deactivate")
@click.argument("user")
@with_appcontext
@commit
def users_deactivate(user):
    """Deactivate a user."""
    user_obj = _datastore.get_user(user)
    if user_obj is None:
        raise click.UsageError("User not found.")
    if _datastore.deactivate_user(user_obj):
        click.secho('User "{0}" has been deactivated.'.format(user), fg="green")
    else:
        click.secho('User "{0}" was already deactivated.'.format(user), fg="yellow")


@users.command(
    "reset_access",
    help="Reset all authentication credentials for user."
    " This includes session, auth token, two-factor"
    " and unified sign in secrets. ",
)
@click.argument("user")
@with_appcontext
@commit
def users_reset_access(user):
    """ Reset all authentication tokens etc."""
    user_obj = _datastore.get_user(user)
    if user_obj is None:
        raise click.UsageError("User not found.")
    _datastore.reset_user_access(user_obj)
    click.secho(
        'User "{user}" authentication credentials have been reset.'.format(user=user),
        fg="green",
    )
