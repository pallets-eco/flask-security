"""
    test_cli
    ~~~~~~~~

    Test command line interface.
"""

from click.testing import CliRunner
import pytest

from flask_security.cli import (
    roles_add,
    roles_create,
    roles_remove,
    roles_add_permissions,
    roles_remove_permissions,
    users_activate,
    users_change_password,
    users_create,
    users_deactivate,
    users_reset_access,
)
from flask_security import verify_password


def test_cli_createuser(script_info):
    """Test create user CLI."""
    runner = CliRunner()

    # Missing params
    result = runner.invoke(users_create, input="1234\n1234\n", obj=script_info)
    assert result.exit_code != 0

    # Create user with invalid email
    result = runner.invoke(
        users_create, ["not-an-email", "--password", "battery staple"], obj=script_info
    )
    assert result.exit_code == 2

    # Create user
    result = runner.invoke(
        users_create,
        ["email@example.tld", "--password", "battery staple"],
        obj=script_info,
    )
    assert result.exit_code == 0

    # create user with email and username
    result = runner.invoke(
        users_create,
        [
            "email1@example.tld",
            "us_phone_number:5551212",
            "--password",
            "battery staple",
        ],
        obj=script_info,
    )
    assert result.exit_code == 0

    # try to activate using username
    result = runner.invoke(users_activate, "5551212", obj=script_info)
    assert result.exit_code == 0


def test_cli_createuser_extraargs(script_info):
    # Test that passing attributes that aren't part of registration form
    # are passed to create_user
    runner = CliRunner()
    result = runner.invoke(
        users_create,
        [
            "email1@example.tld",
            "security_number:666",
            "--password",
            "battery staple",
            "--active",
        ],
        obj=script_info,
    )
    assert result.exit_code == 0
    result = runner.invoke(users_activate, ["email1@example.tld"], obj=script_info)
    assert result.exit_code == 0
    assert "was already activated" in result.output


def test_cli_createuser_normalize(script_info):
    """Test create user CLI that is properly normalizes email and password."""
    runner = CliRunner()

    result = runner.invoke(
        users_create,
        ["email@example.tld", "--password", "battery staple\N{ROMAN NUMERAL ONE}"],
        obj=script_info,
    )
    assert result.exit_code == 0
    assert "email@example.tld" in result.stdout

    app = script_info.load_app()
    with app.app_context():
        user = app.security.datastore.find_user(email="email@example.tld")
        assert verify_password(
            "battery staple\N{LATIN CAPITAL LETTER I}", user.password
        )


def test_cli_createuser_errors(script_info):
    # check that errors are stringified
    runner = CliRunner()
    result = runner.invoke(
        users_create, ["--password", "battery staple"], obj=script_info
    )
    assert result.exit_code == 2
    assert "Email not provided" in result.output


@pytest.mark.babel()
@pytest.mark.app_settings(babel_default_locale="fr_FR")
def test_cli_locale(script_info):
    # Flask_BabelEx required a request context - and click just has an app context.
    try:
        import flask_babelex  # noqa: F401

        pytest.skip("Flask-BabelEx doesn't support app context")
    except ImportError:
        pass
    runner = CliRunner()
    result = runner.invoke(
        users_create, ["--password", "battery staple"], obj=script_info
    )
    assert result.exit_code == 2
    assert "Merci d'indiquer une adresse email" in result.output


def test_cli_createrole(script_info):
    """Test create user CLI."""
    runner = CliRunner()

    # Missing params
    result = runner.invoke(roles_create, ["-d", "Test description"], obj=script_info)
    assert result.exit_code != 0

    # Create role
    result = runner.invoke(
        roles_create, ["superusers", "-d", "Test description"], obj=script_info
    )
    assert result.exit_code == 0


def test_cli_createrole_with_perms(script_info):
    """Test create user CLI."""
    runner = CliRunner()

    # Create role
    result = runner.invoke(
        roles_create,
        ["superusers", "-d", "Test description", "-p", "super, full-write"],
        obj=script_info,
    )

    # Some datastores don't support permissions.
    assert result.exit_code == 0 or result.exit_code == 2


def test_cli_addremove_role(script_info):
    """Test add/remove role."""
    runner = CliRunner()

    # Create a user and a role
    result = runner.invoke(
        users_create, ["a@example.tld", "--password", "battery staple"], obj=script_info
    )
    assert result.exit_code == 0
    result = runner.invoke(roles_create, ["superuser"], obj=script_info)
    assert result.exit_code == 0

    # User not found
    result = runner.invoke(
        roles_add, ["inval@example.tld", "superuser"], obj=script_info
    )
    assert result.exit_code != 0

    # Add:
    result = runner.invoke(roles_add, ["a@example.tld", "invalid"], obj=script_info)
    assert result.exit_code != 0

    result = runner.invoke(
        roles_remove, ["inval@example.tld", "superuser"], obj=script_info
    )
    assert result.exit_code != 0

    # Remove:
    result = runner.invoke(roles_remove, ["a@example.tld", "invalid"], obj=script_info)
    assert result.exit_code != 0

    result = runner.invoke(
        roles_remove, ["b@example.tld", "superuser"], obj=script_info
    )
    assert result.exit_code != 0

    result = runner.invoke(
        roles_remove, ["a@example.tld", "superuser"], obj=script_info
    )
    assert result.exit_code != 0

    # Add:
    result = runner.invoke(roles_add, ["a@example.tld", "superuser"], obj=script_info)
    assert result.exit_code == 0
    result = runner.invoke(roles_add, ["a@example.tld", "superuser"], obj=script_info)
    assert result.exit_code != 0

    # Remove:
    result = runner.invoke(
        roles_remove, ["a@example.tld", "superuser"], obj=script_info
    )
    assert result.exit_code == 0


def test_cli_addremove_permissions(script_info):
    """Test add/remove permissions."""
    runner = CliRunner()
    app = script_info.load_app()

    result = runner.invoke(
        roles_create, ["superusers", "-d", "Test description"], obj=script_info
    )
    assert result.exit_code == 0

    # add permission to non-existent role
    result = runner.invoke(
        roles_add_permissions, ["whatrole", "read, write"], obj=script_info
    )
    assert "Cannot find role" in result.output

    result = runner.invoke(
        roles_add_permissions, ["superusers", "read, write"], obj=script_info
    )

    with app.app_context():
        srole = app.security.datastore.find_role("superusers")
        assert srole.get_permissions() == {"read", "write"}

    assert all(p in result.output for p in ["read", "write", "superusers"])

    # remove permission to non-existent role
    result = runner.invoke(
        roles_remove_permissions, ["whatrole", "read, write"], obj=script_info
    )
    assert "Cannot find role" in result.output

    result = runner.invoke(
        roles_remove_permissions, ["superusers", "write"], obj=script_info
    )
    assert all(p in result.output for p in ["write", "superusers"])

    result = runner.invoke(
        roles_remove_permissions, ["superusers", "whatever, read"], obj=script_info
    )
    # remove permissions doesn't check if existing or not.
    assert all(p in result.output for p in ["read", "superusers"])
    with app.app_context():
        srole = app.security.datastore.find_role("superusers")
        assert srole.get_permissions() == set()


def test_cli_activate_deactivate(script_info):
    """Test create user CLI."""
    runner = CliRunner()

    # Create a user
    result = runner.invoke(
        users_create, ["a@example.tld", "--password", "battery staple"], obj=script_info
    )
    assert result.exit_code == 0

    # Activate
    result = runner.invoke(users_activate, ["in@valid.org"], obj=script_info)
    assert result.exit_code != 0
    result = runner.invoke(users_deactivate, ["in@valid.org"], obj=script_info)
    assert result.exit_code != 0

    result = runner.invoke(users_activate, ["a@example.tld"], obj=script_info)
    assert result.exit_code == 0
    result = runner.invoke(users_activate, ["a@example.tld"], obj=script_info)
    assert result.exit_code == 0

    # Deactivate
    result = runner.invoke(users_deactivate, ["a@example.tld"], obj=script_info)
    assert result.exit_code == 0
    result = runner.invoke(users_deactivate, ["a@example.tld"], obj=script_info)
    assert result.exit_code == 0


def test_cli_reset_user(script_info):
    runner = CliRunner()
    result = runner.invoke(
        users_create,
        [
            "email1@example.tld",
            "us_phone_number:5551212",
            "--password",
            "battery staple",
        ],
        obj=script_info,
    )

    result = runner.invoke(users_reset_access, ["5551212"], obj=script_info)
    assert result.exit_code == 0
    result = runner.invoke(users_reset_access, ["5551212"], obj=script_info)
    assert result.exit_code == 2

    result = runner.invoke(users_reset_access, ["4441212"], obj=script_info)
    assert "User not found" in result.output


def test_cli_change_password(script_info):
    runner = CliRunner()

    runner.invoke(
        users_create,
        ["email1@example.tld", "--password", "battery staple"],
        obj=script_info,
    )
    result = runner.invoke(
        users_change_password,
        ["email1@example.tld", "--password", "battery_staple"],
        obj=script_info,
    )
    assert result.exit_code == 0

    # check too short a password
    result = runner.invoke(
        users_change_password,
        ["email1@example.tld", "--password", "hi"],
        obj=script_info,
    )
    assert result.exit_code == 2
    assert "Password must be at least" in result.output

    # check that password is properly normalized
    result = runner.invoke(
        users_change_password,
        ["email1@example.tld", "--password", "battery staple\N{ROMAN NUMERAL ONE}"],
        obj=script_info,
    )
    assert result.exit_code == 0

    app = script_info.load_app()
    with app.app_context():
        user = app.security.datastore.find_user(email="email1@example.tld")
        assert verify_password(
            "battery staple\N{LATIN CAPITAL LETTER I}", user.password
        )

    result = runner.invoke(users_change_password, ["--help"])
    assert "IDENTITY" in result.output

    # check unknown user
    result = runner.invoke(
        users_change_password,
        ["wrong_email@example.tld", "--password", "battery_staple"],
        obj=script_info,
    )
    assert result.exit_code == 2
    assert "User not found" in result.output
