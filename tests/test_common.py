"""
    test_common
    ~~~~~~~~~~~

    Test common functionality

    :copyright: (c) 2019 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import base64
import json
import re
from http.cookiejar import Cookie
import pytest

from flask import Blueprint

from flask_security import uia_email_mapper
from flask_security.utils import hash_data

from tests.test_utils import (
    authenticate,
    json_authenticate,
    get_num_queries,
    hash_password,
    logout,
    populate_data,
    verify_token,
)


def test_login_view(client):
    response = client.get("/login")
    assert b"<h1>Login</h1>" in response.data


def test_authenticate(client):
    response = authenticate(client)
    assert response.status_code == 302
    response = authenticate(client, follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data


def test_authenticate_with_next(client):
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=/page1", data=data, follow_redirects=True)
    assert b"Page 1" in response.data


def test_authenticate_with_next_bp(app, client):
    api = Blueprint("api", __name__)

    @api.route("/info")
    def info():
        pass

    app.register_blueprint(api, url_prefix="/api")
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=api.info", data=data, follow_redirects=False)
    assert response.status_code == 302
    assert "api/info" in response.location


def test_authenticate_with_invalid_next(client, get_message):
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http://google.com", data=data)
    assert get_message("INVALID_REDIRECT") in response.data


def test_authenticate_with_invalid_malformed_next(client, get_message):
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http:///google.com", data=data)
    assert get_message("INVALID_REDIRECT") in response.data


def test_authenticate_with_subdomain_next(app, client, get_message):
    app.config["SERVER_NAME"] = "lp.com"
    app.config["SECURITY_REDIRECT_ALLOW_SUBDOMAINS"] = True
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http://sub.lp.com", data=data)
    assert response.status_code == 302


def test_authenticate_with_root_domain_next(app, client, get_message):
    app.config["SERVER_NAME"] = "lp.com"
    app.config["SECURITY_SUBDOMAIN"] = "auth"
    app.config["SECURITY_REDIRECT_ALLOW_SUBDOMAINS"] = True
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http://lp.com", data=data)
    assert response.status_code == 302


def test_authenticate_with_invalid_subdomain_next(app, client, get_message):
    app.config["SERVER_NAME"] = "lp.com"
    app.config["SECURITY_REDIRECT_ALLOW_SUBDOMAINS"] = True
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http://sub.lp.net", data=data)
    assert get_message("INVALID_REDIRECT") in response.data


def test_authenticate_with_subdomain_next_default_config(app, client, get_message):
    app.config["SERVER_NAME"] = "lp.com"
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http://sub.lp.com", data=data)
    assert get_message("INVALID_REDIRECT") in response.data


def test_authenticate_case_insensitive_email(app, client):
    response = authenticate(client, "MATT@lp.com", follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data


def test_authenticate_with_invalid_input(client, get_message):
    response = client.post(
        "/login", data="{}", headers={"Content-Type": "application/json"}
    )
    assert get_message("EMAIL_NOT_PROVIDED") in response.data


@pytest.mark.settings(post_login_view="/post_login")
def test_get_already_authenticated(client):
    response = authenticate(client, follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data
    response = client.get("/login", follow_redirects=True)
    assert b"Post Login" in response.data


@pytest.mark.settings(post_login_view="/post_login")
def test_get_already_authenticated_next(client):
    response = authenticate(client, follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data
    # This should NOT override post_login_view due to potential redirect loops.
    response = client.get("/login?next=/page1", follow_redirects=True)
    assert b"Post Login" in response.data


@pytest.mark.settings(post_login_view="/post_login")
def test_post_already_authenticated(client):
    response = authenticate(client, follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login", data=data, follow_redirects=True)
    assert b"Post Login" in response.data
    # This should NOT override post_login_view due to potential redirect loops.
    response = client.post("/login?next=/page1", data=data, follow_redirects=True)
    assert b"Post Login" in response.data


def test_login_form(client):
    response = client.post("/login", data={"email": "matt@lp.com"})
    assert b"matt@lp.com" in response.data
    assert re.search(b'<input[^>]*type="email"[^>]*>', response.data)


def test_unprovided_username(client, get_message):
    response = authenticate(client, "")
    assert get_message("EMAIL_NOT_PROVIDED") in response.data


def test_unprovided_password(client, get_message):
    response = authenticate(client, password="")
    assert get_message("PASSWORD_NOT_PROVIDED") in response.data


def test_invalid_user(client, get_message):
    response = authenticate(client, email="bogus@bogus.com")
    assert get_message("USER_DOES_NOT_EXIST") in response.data


def test_bad_password(client, get_message):
    response = authenticate(client, password="bogus")
    assert get_message("INVALID_PASSWORD") in response.data


def test_inactive_user(client, get_message):
    response = authenticate(client, "tiya@lp.com", "password")
    assert get_message("DISABLED_ACCOUNT") in response.data


def test_inactive_forbids(app, client, get_message):
    """Make sure that existing session doesn't work after
    user marked inactive
    """
    response = authenticate(client, follow_redirects=True)
    assert response.status_code == 200
    # make sure can access restricted page
    response = client.get("/profile", follow_redirects=True)
    assert b"Profile Page" in response.data

    # deactivate matt
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        app.security.datastore.deactivate_user(user)
        app.security.datastore.commit()

    response = client.get("/profile", follow_redirects=True)
    # should be thrown back to login page.
    assert response.status_code == 200
    assert b"Please log in to access this page" in response.data


@pytest.mark.settings(unauthorized_view=None)
def test_inactive_forbids_token(app, client_nc, get_message):
    """Make sure that existing token doesn't work after
    user marked inactive
    """
    response = json_authenticate(client_nc)
    assert response.status_code == 200
    token = response.json["response"]["user"]["authentication_token"]
    headers = {"Authentication-Token": token}
    # make sure can access restricted page
    response = client_nc.get("/token", headers=headers)
    assert b"Token Authentication" in response.data

    # deactivate matt
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        app.security.datastore.deactivate_user(user)
        app.security.datastore.commit()

    response = client_nc.get("/token", content_type="application/json", headers=headers)
    assert response.status_code == 401


def test_inactive_forbids_basic(app, client, get_message):
    """Make sure that basic auth doesn't work if user deactivated"""

    # Should properly work.
    response = client.get(
        "/multi_auth",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"joe@lp.com:password").decode("utf-8")
        },
    )
    assert b"Session, Token, Basic" in response.data

    # deactivate joe
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="joe@lp.com")
        app.security.datastore.deactivate_user(user)
        app.security.datastore.commit()

    response = client.get(
        "/multi_auth",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"joe@lp.com:password").decode("utf-8")
        },
    )
    assert b"You are not authenticated" in response.data


def test_unset_password(client, get_message):
    response = authenticate(client, "jess@lp.com", "password")
    assert get_message("PASSWORD_NOT_SET") in response.data


def test_logout(client):
    authenticate(client)
    response = logout(client, follow_redirects=True)
    assert b"Home Page" in response.data


def test_logout_post(client):
    authenticate(client)
    response = client.post("/logout", content_type="application/json")
    assert response.status_code == 200
    assert response.json["meta"]["code"] == 200


def test_logout_with_next_invalid(client, get_message):
    authenticate(client)
    response = client.get("/logout?next=http://google.com")
    assert "google.com" not in response.location


def test_logout_with_next(client):
    authenticate(client)
    response = client.get("/logout?next=/page1", follow_redirects=True)
    assert b"Page 1" in response.data


def test_missing_session_access(client, get_message):
    response = client.get("/profile", follow_redirects=True)
    assert get_message("LOGIN") in response.data


def test_has_session_access(client):
    authenticate(client)
    response = client.get("/profile", follow_redirects=True)
    assert b"profile" in response.data


def test_authorized_access(client):
    authenticate(client)
    response = client.get("/admin")
    assert b"Admin Page" in response.data


def test_unauthorized_access(client, get_message):
    authenticate(client, "joe@lp.com")
    response = client.get("/admin", follow_redirects=True)
    assert response.status_code == 403


@pytest.mark.settings(unauthorized_view=lambda: None)
def test_unauthorized_access_with_referrer(client, get_message):
    authenticate(client, "joe@lp.com")
    response = client.get("/admin", headers={"referer": "/admin"})
    assert response.headers["Location"] != "/admin"
    client.get(response.headers["Location"])

    response = client.get(
        "/admin?a=b", headers={"referer": "http://localhost/admin?x=y"}
    )
    assert response.headers["Location"] == "http://localhost/"
    client.get(response.headers["Location"])

    response = client.get(
        "/admin", headers={"referer": "/admin"}, follow_redirects=True
    )
    assert response.data.count(get_message("UNAUTHORIZED")) == 1

    # When referrer is from another path and unauthorized,
    # we expect a temp redirect (302) to the referer
    response = client.get("/admin?w=s", headers={"referer": "/profile"})
    assert response.status_code == 302
    assert response.headers["Location"] == "http://localhost/profile"


@pytest.mark.settings(unauthorized_view="/unauthz")
def test_roles_accepted(clients):
    # This specificaly tests that we can pass a URL for unauthorized_view.
    for user in ("matt@lp.com", "joe@lp.com"):
        authenticate(clients, user)
        response = clients.get("/admin_or_editor")
        assert b"Admin or Editor Page" in response.data
        logout(clients)

    authenticate(clients, "jill@lp.com")
    response = clients.get("/admin_or_editor", follow_redirects=True)
    assert b"Unauthorized" in response.data


@pytest.mark.settings(unauthorized_view="unauthz")
def test_permissions_accepted(clients):
    for user in ("matt@lp.com", "joe@lp.com"):
        authenticate(clients, user)
        response = clients.get("/admin_perm")
        assert b"Admin Page with full-write or super" in response.data
        logout(clients)

    authenticate(clients, "jill@lp.com")
    response = clients.get("/admin_perm", follow_redirects=True)
    assert b"Unauthorized" in response.data


@pytest.mark.settings(unauthorized_view="unauthz")
def test_permissions_required(clients):
    for user in ["matt@lp.com"]:
        authenticate(clients, user)
        response = clients.get("/admin_perm_required")
        assert b"Admin Page required" in response.data
        logout(clients)

    authenticate(clients, "joe@lp.com")
    response = clients.get("/admin_perm_required", follow_redirects=True)
    assert b"Unauthorized" in response.data


@pytest.mark.settings(unauthorized_view="unauthz")
def test_unauthenticated_role_required(client, get_message):
    response = client.get("/admin", follow_redirects=True)
    assert get_message("UNAUTHORIZED") in response.data


@pytest.mark.settings(unauthorized_view="unauthz")
def test_multiple_role_required(clients):
    for user in ("matt@lp.com", "joe@lp.com"):
        authenticate(clients, user)
        response = clients.get("/admin_and_editor", follow_redirects=True)
        assert b"Unauthorized" in response.data
        clients.get("/logout")

    authenticate(clients, "dave@lp.com")
    response = clients.get("/admin_and_editor", follow_redirects=True)
    assert b"Admin and Editor Page" in response.data


def test_ok_json_auth(client):
    response = json_authenticate(client)
    assert response.json["meta"]["code"] == 200
    assert "authentication_token" in response.json["response"]["user"]


def test_invalid_json_auth(client):
    response = json_authenticate(client, password="junk")
    assert b'"code": 400' in response.data


def test_token_auth_via_querystring_valid_token(client):
    response = json_authenticate(client)
    token = response.json["response"]["user"]["authentication_token"]
    response = client.get("/token?auth_token=" + token)
    assert b"Token Authentication" in response.data


def test_token_auth_via_header_valid_token(client):
    response = json_authenticate(client)
    token = response.json["response"]["user"]["authentication_token"]
    headers = {"Authentication-Token": token}
    response = client.get("/token", headers=headers)
    assert b"Token Authentication" in response.data


def test_token_auth_via_querystring_invalid_token(client):
    response = client.get("/token?auth_token=X", headers={"Accept": "application/json"})
    assert response.status_code == 401


def test_token_auth_via_header_invalid_token(client):
    response = client.get(
        "/token", headers={"Authentication-Token": "X", "Accept": "application/json"}
    )
    assert response.status_code == 401


def test_http_auth(client):
    # browsers expect 401 response with WWW-Authenticate header - which will prompt
    # them to pop up a login form.
    response = client.get("/http", headers={})
    assert response.status_code == 401
    assert b"You are not authenticated" in response.data
    assert "WWW-Authenticate" in response.headers
    assert 'Basic realm="Login Required"' == response.headers["WWW-Authenticate"]

    # Now provide correct credentials
    response = client.get(
        "/http",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"joe@lp.com:password").decode("utf-8")
        },
    )
    assert b"HTTP Authentication" in response.data


@pytest.mark.settings(
    USER_IDENTITY_ATTRIBUTES=[
        {"email": {"mapper": uia_email_mapper}},
        {"username": {"mapper": lambda x: x}},
    ]
)
def test_http_auth_username(client):
    response = client.get(
        "/http",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"jill:password").decode("utf-8")
        },
    )
    assert b"HTTP Authentication" in response.data


def test_http_auth_no_authorization(client):
    response = client.get(
        "/http_admin_required",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"joe@lp.com:password").decode("utf-8")
        },
    )
    assert response.status_code == 403


def test_http_auth_no_authorization_json(client, get_message):
    response = client.get(
        "/http_admin_required",
        headers={
            "accept": "application/json",
            "Authorization": "Basic %s"
            % base64.b64encode(b"joe@lp.com:password").decode("utf-8"),
        },
    )
    assert response.status_code == 403
    assert response.headers["Content-Type"] == "application/json"


@pytest.mark.settings(backwards_compat_unauthn=True)
def test_http_auth_no_authentication(client, get_message):
    response = client.get("/http", headers={})
    assert response.status_code == 401
    assert b"<h1>Unauthorized</h1>" in response.data
    assert "WWW-Authenticate" in response.headers
    assert 'Basic realm="Login Required"' == response.headers["WWW-Authenticate"]


@pytest.mark.settings(backwards_compat_unauthn=False)
def test_http_auth_no_authentication_json(client, get_message):
    response = client.get("/http", headers={"accept": "application/json"})
    assert response.status_code == 401
    assert response.json["response"]["error"].encode("utf-8") == get_message(
        "UNAUTHENTICATED"
    )
    assert response.headers["Content-Type"] == "application/json"


@pytest.mark.settings(backwards_compat_unauthn=True)
def test_invalid_http_auth_invalid_username(client):
    response = client.get(
        "/http",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"bogus:bogus").decode("utf-8")
        },
    )
    assert b"<h1>Unauthorized</h1>" in response.data
    assert "WWW-Authenticate" in response.headers
    assert 'Basic realm="Login Required"' == response.headers["WWW-Authenticate"]


@pytest.mark.settings(backwards_compat_unauthn=False)
def test_invalid_http_auth_invalid_username_json(client, get_message):
    # Even with JSON - Basic Auth required a WWW-Authenticate header response.
    response = client.get(
        "/http",
        headers={
            "accept": "application/json",
            "Authorization": "Basic %s"
            % base64.b64encode(b"bogus:bogus").decode("utf-8"),
        },
    )
    assert response.status_code == 401
    assert response.json["response"]["error"].encode("utf-8") == get_message(
        "UNAUTHENTICATED"
    )
    assert response.headers["Content-Type"] == "application/json"
    assert "WWW-Authenticate" in response.headers


@pytest.mark.settings(backwards_compat_unauthn=True)
def test_invalid_http_auth_bad_password(client):
    response = client.get(
        "/http",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"joe@lp.com:bogus").decode("utf-8")
        },
    )
    assert b"<h1>Unauthorized</h1>" in response.data
    assert "WWW-Authenticate" in response.headers
    assert 'Basic realm="Login Required"' == response.headers["WWW-Authenticate"]


@pytest.mark.settings(backwards_compat_unauthn=True)
def test_custom_http_auth_realm(client):
    response = client.get(
        "/http_custom_realm",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"joe@lp.com:bogus").decode("utf-8")
        },
    )
    assert b"<h1>Unauthorized</h1>" in response.data
    assert "WWW-Authenticate" in response.headers
    assert 'Basic realm="My Realm"' == response.headers["WWW-Authenticate"]


def test_multi_auth_basic(client):
    response = client.get(
        "/multi_auth",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"joe@lp.com:password").decode("utf-8")
        },
    )
    assert b"Basic" in response.data

    response = client.get("/multi_auth")
    # Default unauthn with basic is to return 401 with WWW-Authenticate Header
    # so that browser pops up a username/password dialog
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


@pytest.mark.settings(backwards_compat_unauthn=True)
def test_multi_auth_basic_invalid(client):
    response = client.get(
        "/multi_auth",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"bogus:bogus").decode("utf-8")
        },
    )
    assert b"<h1>Unauthorized</h1>" in response.data
    assert "WWW-Authenticate" in response.headers
    assert 'Basic realm="Login Required"' == response.headers["WWW-Authenticate"]

    response = client.get("/multi_auth")
    assert response.status_code == 401


def test_multi_auth_token(client):
    response = json_authenticate(client)
    token = response.json["response"]["user"]["authentication_token"]
    response = client.get("/multi_auth?auth_token=" + token)
    assert b"Token" in response.data


def test_multi_auth_session(client):
    authenticate(client)
    response = client.get("/multi_auth")
    assert b"Session" in response.data


def test_authenticated_loop(client):
    # If user is already authenticated say via session, and then hits an endpoint
    # protected with @auth_token_required() - then they will be redirected to the login
    # page which will simply note the current user is already logged in and redirect
    # to POST_LOGIN_VIEW. Between 3.3.0 and 3.4.4 - this redirect would honor the 'next'
    # parameter - thus redirecting back to the endpoint that caused the redirect in the
    # first place - thus an infinite loop.
    authenticate(client)

    response = client.get("/token", follow_redirects=True)
    assert response.status_code == 200
    assert b"Home Page" in response.data


def test_user_deleted_during_session_reverts_to_anonymous_user(app, client):
    authenticate(client)

    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        app.security.datastore.delete_user(user)
        app.security.datastore.commit()

    response = client.get("/")
    assert b"Hello matt@lp.com" not in response.data


def test_remember_token(client):
    response = authenticate(client, follow_redirects=False)
    client.cookie_jar.clear_session_cookies()
    response = client.get("/profile")
    assert b"profile" in response.data


def test_request_loader_does_not_fail_with_invalid_token(client):
    c = Cookie(
        version=0,
        name="remember_token",
        value="None",
        port=None,
        port_specified=False,
        domain="www.example.com",
        domain_specified=False,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure=False,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": None},
        rfc2109=False,
    )

    client.cookie_jar.set_cookie(c)
    response = client.get("/")
    assert b"BadSignature" not in response.data


def test_sending_auth_token_with_json(client):
    response = json_authenticate(client)
    token = response.json["response"]["user"]["authentication_token"]
    data = '{"auth_token": "%s"}' % token
    response = client.post(
        "/token", data=data, headers={"Content-Type": "application/json"}
    )
    assert b"Token Authentication" in response.data


def test_json_not_dict(client):
    response = client.post(
        "/json",
        data=json.dumps(["thing1", "thing2"]),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200


def test_login_info(client):
    # Make sure we can get user info when logged in already.

    json_authenticate(client)
    response = client.get("/login", headers={"Content-Type": "application/json"})
    assert response.status_code == 200
    assert response.json["response"]["user"]["email"] == "matt@lp.com"
    assert "last_update" in response.json["response"]["user"]

    response = client.get("/login", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json["response"]["user"]["email"] == "matt@lp.com"
    assert "last_update" in response.json["response"]["user"]


@pytest.mark.registerable()
@pytest.mark.settings(post_login_view="/anon_required")
def test_anon_required(client, get_message):
    """ If logged in, should get 'anonymous_user_required' redirect """
    response = authenticate(client, follow_redirects=False)
    response = client.get("/register")
    assert "location" in response.headers
    assert "/anon_required" in response.location


@pytest.mark.registerable()
@pytest.mark.settings(post_login_view="/anon_required")
def test_anon_required_json(client, get_message):
    """ If logged in, should get 'anonymous_user_required' response """
    authenticate(client, follow_redirects=False)
    response = client.get("/register", headers={"Accept": "application/json"})
    assert response.status_code == 400
    assert response.json["response"]["error"].encode("utf-8") == get_message(
        "ANONYMOUS_USER_REQUIRED"
    )


def test_change_uniquifier(app, client_nc):
    # make sure that existing token no longer works once we change the uniquifier

    response = json_authenticate(client_nc)
    token = response.json["response"]["user"]["authentication_token"]
    verify_token(client_nc, token)

    # now change uniquifier
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        app.security.datastore.reset_user_access(user)
        app.security.datastore.commit()

    verify_token(client_nc, token, status=401)

    # get new token and verify it works
    response = json_authenticate(client_nc)
    token = response.json["response"]["user"]["authentication_token"]
    verify_token(client_nc, token)


def test_verifying_token_from_version_3x(app, client_nc):
    """
    Check token generated with flask security 3.x, which has different form
    than token from version 4.0.0, can be verified
    """

    def get_auth_token_version_3x(app, user):
        """
        Copy of algorithm that generated user token in version 3.x
        """
        data = [str(user.id), hash_data(user.password)]
        if hasattr(user, "fs_uniquifier"):
            data.append(user.fs_uniquifier)
        return app.security.remember_token_serializer.dumps(data)

    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")

        token = get_auth_token_version_3x(app, user)

        data = app.security.remember_token_serializer.loads(
            token, max_age=app.security.token_max_age
        )

        assert user.verify_auth_token(data) is True


def test_change_token_uniquifier(app):
    # make sure that existing token no longer works once we change the token uniquifier
    from sqlalchemy import Column, String
    from flask_sqlalchemy import SQLAlchemy
    from flask_security.models import fsqla_v2 as fsqla
    from flask_security import Security, SQLAlchemyUserDatastore

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    db = SQLAlchemy(app)

    fsqla.FsModels.set_db_info(db)

    class Role(db.Model, fsqla.FsRoleMixin):
        pass

    class User(db.Model, fsqla.FsUserMixin):
        fs_token_uniquifier = Column(String(64), unique=True, nullable=False)

    with app.app_context():
        db.create_all()

    ds = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(app, datastore=ds)

    with app.app_context():
        ds.create_user(
            email="matt@lp.com",
            password=hash_password("password"),
        )
        ds.commit()

        client_nc = app.test_client(use_cookies=False)

        response = json_authenticate(client_nc)
        token = response.json["response"]["user"]["authentication_token"]
        verify_token(client_nc, token)

        # now change uniquifier
        with app.test_request_context("/"):
            user = app.security.datastore.find_user(email="matt@lp.com")
            app.security.datastore.reset_user_access(user)
            app.security.datastore.commit()

        verify_token(client_nc, token, status=401)

        # get new token and verify it works
        response = json_authenticate(client_nc)
        token = response.json["response"]["user"]["authentication_token"]
        verify_token(client_nc, token)


def test_null_token_uniquifier(app):
    # If existing record has a null fs_token_uniquifier, should be set on first use.
    from sqlalchemy import Column, String
    from flask_sqlalchemy import SQLAlchemy
    from flask_security.models import fsqla_v2 as fsqla
    from flask_security import Security, SQLAlchemyUserDatastore

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    db = SQLAlchemy(app)

    fsqla.FsModels.set_db_info(db)

    class Role(db.Model, fsqla.FsRoleMixin):
        pass

    class User(db.Model, fsqla.FsUserMixin):
        fs_token_uniquifier = Column(String(64), unique=True, nullable=True)

    with app.app_context():
        db.create_all()

    ds = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(app, datastore=ds)

    with app.app_context():
        ds.create_user(
            email="matt@lp.com",
            password=hash_password("password"),
        )
        ds.commit()

        # manually null out fs_token_uniquifier
        user = ds.find_user(email="matt@lp.com")
        user.fs_token_uniquifier = None
        ds.put(user)
        ds.commit()

        client_nc = app.test_client(use_cookies=False)

        response = json_authenticate(client_nc)
        token = response.json["response"]["user"]["authentication_token"]
        verify_token(client_nc, token)


def test_token_query(in_app_context):
    # Verify that when authenticating with auth token (and not session)
    # that there is just one DB query to get user.
    app = in_app_context
    populate_data(app)
    client_nc = app.test_client(use_cookies=False)

    response = json_authenticate(client_nc)
    token = response.json["response"]["user"]["authentication_token"]
    current_nqueries = get_num_queries(app.security.datastore)

    response = client_nc.get(
        "/token",
        headers={"Content-Type": "application/json", "Authentication-Token": token},
    )
    assert response.status_code == 200
    end_nqueries = get_num_queries(app.security.datastore)
    assert current_nqueries is None or end_nqueries == (current_nqueries + 1)


def test_session_query(in_app_context):
    # Verify that when authenticating with auth token (but also sending session)
    # that there are 2 DB queries to get user.
    # This is since the session will load one - but auth_token_required needs to
    # verify that the TOKEN is valid (and it is possible that the user_id in the
    # session is different that the one in the token (huh?)
    app = in_app_context
    populate_data(app)
    client = app.test_client()

    response = json_authenticate(client)
    token = response.json["response"]["user"]["authentication_token"]
    current_nqueries = get_num_queries(app.security.datastore)

    response = client.get(
        "/token",
        headers={"Content-Type": "application/json", "Authentication-Token": token},
    )
    assert response.status_code == 200
    end_nqueries = get_num_queries(app.security.datastore)
    assert current_nqueries is None or end_nqueries == (current_nqueries + 2)


@pytest.mark.changeable()
def test_no_get_auth_token(app, client):
    # Test that GETs don't return an auth token. This is a security issue since
    # GETs aren't protected with CSRF
    authenticate(client)
    response = client.get(
        "/login?include_auth_token", headers={"Content-Type": "application/json"}
    )
    assert "authentication_token" not in response.json["response"]["user"]

    data = dict(
        password="password",
        new_password="new strong password",
        new_password_confirm="new strong password",
    )
    response = client.get(
        "/change?include_auth_token",
        json=data,
        headers={"Content-Type": "application/json"},
    )
    assert "authentication_token" not in response.json["response"]["user"]
