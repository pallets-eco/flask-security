"""
    test_basic
    ~~~~~~~~~~~

    Test common functionality

    :copyright: (c) 2019-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import base64
from datetime import datetime, timedelta, timezone
import json
import re
import pytest

from flask import Blueprint, g

from flask_security import uia_email_mapper
from flask_security.decorators import auth_required
from flask_principal import identity_loaded
from freezegun import freeze_time

from tests.test_utils import (
    authenticate,
    capture_flashes,
    capture_queries,
    check_location,
    get_auth_token_version_3x,
    get_form_action,
    get_form_input,
    hash_password,
    init_app_with_options,
    is_authenticated,
    json_authenticate,
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


@pytest.mark.settings(anonymous_user_disabled=True)
def test_authenticate_no_anon(client):
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


@pytest.mark.settings(flash_messages=False)
def test_authenticate_with_invalid_next_json(client, get_message):
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http://google.com", json=data)
    assert response.json["response"]["errors"][0].encode() == get_message(
        "INVALID_REDIRECT"
    )


def test_authenticate_with_invalid_malformed_next(client, get_message):
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http:///google.com", data=data)
    assert get_message("INVALID_REDIRECT") in response.data


def test_unauthenticated(app, client, get_message):
    from flask_security import user_unauthenticated
    from flask import request

    recvd = []

    @user_unauthenticated.connect_via(app)
    def un(myapp, **extra):
        assert request.path == "/profile"
        recvd.append("gotit")

    response = client.get("/profile", follow_redirects=False)
    assert len(recvd) == 1
    assert response.location == "/login?next=/profile"


@pytest.mark.flask_async()
def test_unauthenticated_async(app, client, get_message):
    from flask_security import user_unauthenticated
    from flask import request

    recvd = []

    @user_unauthenticated.connect_via(app)
    async def un(myapp, **extra):
        assert request.path == "/profile"
        recvd.append("gotit")

    response = client.get("/profile", follow_redirects=False)
    assert len(recvd) == 1
    assert response.location == "/login?next=/profile"


def test_login_template_next(client):
    # Test that our login template propagates next.
    response = client.get("/profile", follow_redirects=True)
    assert "?next=/profile" in response.request.url
    login_url = get_form_action(response)
    response = client.post(
        login_url,
        data=dict(email="matt@lp.com", password="password"),
        follow_redirects=True,
    )
    assert b"Profile Page" in response.data


def test_authenticate_with_subdomain_next(app, client, get_message):
    app.config["SERVER_NAME"] = "lp.com"
    app.config["SECURITY_REDIRECT_ALLOW_SUBDOMAINS"] = True
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http://sub.lp.com", data=data)
    assert response.status_code == 302
    assert response.location == "http://sub.lp.com"


@pytest.mark.settings(subdomain="auth")
def test_authenticate_with_root_domain_next(app, client, get_message):
    app.config["SERVER_NAME"] = "lp.com"
    app.config["SECURITY_REDIRECT_ALLOW_SUBDOMAINS"] = True
    data = dict(email="matt@lp.com", password="password")
    response = client.post("http://auth.lp.com/login?next=http://lp.com", data=data)
    assert response.status_code == 302
    assert response.location == "http://lp.com"


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


@pytest.mark.settings(
    redirect_base_domain="bigidea.org", redirect_allowed_subdomains=["my.photo", "blog"]
)
def test_allow_subdomains(app, client, get_message):
    app.config["SERVER_NAME"] = "app.bigidea.org"
    data = dict(email="matt@lp.com", password="password")
    # not in subdomain allowed list
    response = client.post("/login?next=http://blog2.bigidea.org", data=data)
    assert get_message("INVALID_REDIRECT") in response.data

    response = client.post("/login?next=http://my.photo.bigidea.org/image", data=data)
    assert response.location == "http://my.photo.bigidea.org/image"


@pytest.mark.settings(
    redirect_base_domain="bigidea.org", redirect_allowed_subdomains=[]
)
def test_redirect_allow_subdomains(app, client, get_message):
    app.config["SERVER_NAME"] = "bigidea.org"
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http://blog2.bigidea.org", data=data)
    assert get_message("INVALID_REDIRECT") in response.data
    response = client.post("/login?next=http://bigidea.org/imin", data=data)
    assert response.location == "http://bigidea.org/imin"


@pytest.mark.settings(
    post_login_view="http://blog.bigidea.org/post_login",
    redirect_base_domain="bigidea.org",
    redirect_allowed_subdomains=["my.photo", "blog"],
)
def test_view_redirect(app, client, get_message):
    app.config["SERVER_NAME"] = "bigidea.org"
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login", data=data)
    assert response.location == "http://blog.bigidea.org/post_login"


def test_authenticate_case_insensitive_email(app, client):
    response = authenticate(client, "MATT@lp.com", follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data


def test_authenticate_with_invalid_input(client, get_message):
    response = client.post(
        "/login",
        json=dict(password="password"),
        headers={"Content-Type": "application/json"},
    )
    assert get_message("USER_DOES_NOT_EXIST") in response.data


@pytest.mark.settings(post_login_view="/post_login")
def test_get_already_authenticated(client):
    response = authenticate(client, follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data
    response = client.get("/login", follow_redirects=True)
    assert b"Post Login" in response.data

    # should still get extra goodies
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    response = client.get("/login", headers=headers)
    assert response.status_code == 200

    jresponse = response.json["response"]
    assert all(a in jresponse for a in ["identity_attributes"])
    assert "authentication_token" not in jresponse["user"]
    assert all(a in jresponse["user"] for a in ["email", "last_update"])


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


@pytest.mark.settings(username_enable=True)
def test_login_form_username(client):
    # If USERNAME_ENABLE is set then login form should have a both an Email and
    # StringField
    response = client.get("/login")
    # Should be both email with Email type and username with autocomplete
    assert re.search(b'<input[^>]*type="email"[^>]*>', response.data)
    assert re.search(b'<input[^>]*autocomplete="username"[^>]*>', response.data)
    assert re.search(b'<input[^>]*autocomplete="current-password"[^>]*>', response.data)


@pytest.mark.settings(username_enable=True, username_required=True)
def test_login_form_username_required(app, client):
    # If username required - we should still be able to login with email alone
    # given default user_identity_attributes
    response = client.post(
        "/login", data=dict(email="matt@lp.com", password="password")
    )
    assert check_location(app, response.location, "/")


@pytest.mark.confirmable()
@pytest.mark.settings(
    return_generic_responses=True, requires_confirmation_error_view="/confirm"
)
def test_generic_response(app, client, get_message):
    response = client.post(
        "/login", data=dict(email="mattwho@lp.com", password="forgot")
    )
    assert get_message("GENERIC_AUTHN_FAILED") in response.data
    response = client.post("/login", data=dict(email="matt@lp.com", password="forgot"))
    assert get_message("GENERIC_AUTHN_FAILED") in response.data

    response = client.post(
        "/login", json=dict(email="mattwho@lp.com", password="forgot")
    )
    # make sure no field error key.
    assert list(response.json["response"]["field_errors"].keys()) == [""]
    assert len(response.json["response"]["field_errors"][""]) == 1
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "GENERIC_AUTHN_FAILED"
    )
    response = client.post("/login", json=dict(email="matt@lp.com", password="forgot"))
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "GENERIC_AUTHN_FAILED"
    )

    # make sure don't get confirmation required
    with capture_flashes() as flashes:
        response = client.post(
            "/login",
            data=dict(email="mattwho@lp.com", password="password"),
            follow_redirects=False,
        )
        assert response.status_code == 200
    assert len(flashes) == 0


@pytest.mark.registerable()
@pytest.mark.settings(username_enable=True, return_generic_responses=True)
def test_generic_response_username(app, client, get_message):
    data = dict(
        email="dude@lp.com",
        username="dude",
        password="awesome sunset",
    )
    response = client.post("/register", json=data)
    assert response.headers["Content-Type"] == "application/json"
    assert response.status_code == 200
    logout(client)

    response = client.post(
        "/login", data=dict(username="dude2", password="awesome sunset")
    )
    assert get_message("GENERIC_AUTHN_FAILED") in response.data

    response = client.post("/login", json=dict(username="dude2", password="forgot"))
    # make sure no field error key.
    assert list(response.json["response"]["field_errors"].keys()) == [""]
    assert len(response.json["response"]["field_errors"][""]) == 1
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "GENERIC_AUTHN_FAILED"
    )


def test_unprovided_username(client, get_message):
    response = authenticate(client, "")
    assert get_message("USER_DOES_NOT_EXIST") in response.data


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

    response = client.get("/profile", follow_redirects=False)
    print(response.data)
    # should be thrown back to login page.
    assert response.status_code == 302
    assert response.location == "/login?next=/profile"


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
    assert get_message("UNAUTHENTICATED")[0] in response.data


def test_unset_password(client, get_message):
    response = authenticate(client, "jess@lp.com", "password")
    assert get_message("INVALID_PASSWORD") in response.data
    response = authenticate(client, "jess@lp.com", "")
    assert get_message("PASSWORD_NOT_PROVIDED") in response.data


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
    assert get_message("UNAUTHENTICATED") in response.data


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


def test_unauthorized_callable_view(app, sqlalchemy_datastore, get_message):
    # Test various options using custom unauthorized view
    def unauthz_view():
        from flask import request

        if request.path == "/admin":
            return None
        elif request.path == "/admin_perm":
            return ""
        elif request.path == "/admin_and_editor":
            return "/profile"
        elif request.path == "/simple":
            # N.B. security issue - app should verify this is local
            return request.referrer
        else:
            return "not_implemented"

    app.config["SECURITY_UNAUTHORIZED_VIEW"] = unauthz_view
    init_app_with_options(app, sqlalchemy_datastore)
    client = app.test_client()
    # activate tiya
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="tiya@lp.com")
        app.security.datastore.activate_user(user)
        app.security.datastore.commit()
    authenticate(client, "tiya@lp.com")
    assert is_authenticated(client, get_message)

    response = client.get("/admin")
    assert response.status_code == 403
    response = client.get("/admin_perm")
    assert response.status_code == 403

    response = client.get("/admin_and_editor", follow_redirects=False)
    assert check_location(app, response.location, "/profile")
    response = client.get(response.location)
    assert response.data.count(get_message("UNAUTHORIZED")) == 1

    response = client.get(
        "/simple", headers={"referer": "/myhome"}, follow_redirects=False
    )
    assert check_location(app, response.location, "/myhome")


def test_unauthorized_url_view(app, sqlalchemy_datastore):
    # Test unknown endpoint basically results in redirect to the given string.
    app.config["SECURITY_UNAUTHORIZED_VIEW"] = ".myendpoint"
    init_app_with_options(app, sqlalchemy_datastore)
    client = app.test_client()
    authenticate(client, "tiya@lp.com")
    response = client.get("/admin")
    assert response.status_code == 302
    check_location(app, response.location, ".myendpoint")


@pytest.mark.settings(unauthorized_view="/unauthz")
def test_roles_accepted(clients):
    # This specifically tests that we can pass a URL for unauthorized_view.
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


def test_token_auth_invalid_for_session_auth(client):
    # when user is loaded from token data, session authentication should fail.
    response = json_authenticate(client)
    token = response.json["response"]["user"]["authentication_token"]
    # logout so session doesn't contain valid user details
    logout(client)
    headers = {"Authentication-Token": token, "Accept": "application/json"}
    response = client.get("/session", headers=headers)
    assert response.status_code == 401


def test_per_user_expired_token(app, client_nc):
    # Test expiry in auth_token using callable
    with freeze_time("2024-01-01"):

        def exp(user):
            assert user.email == "matt@lp.com"
            return int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp())

        app.config["SECURITY_TOKEN_EXPIRE_TIMESTAMP"] = exp

        response = json_authenticate(client_nc)
        token = response.json["response"]["user"]["authentication_token"]

    verify_token(client_nc, token, status=401)


def test_per_user_not_expired_token(app, client_nc):
    # Test expiry in auth_token using callable
    def exp(user):
        assert user.email == "matt@lp.com"
        return int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp())

    app.config["SECURITY_TOKEN_EXPIRE_TIMESTAMP"] = exp

    response = json_authenticate(client_nc)
    token = response.json["response"]["user"]["authentication_token"]
    verify_token(client_nc, token)


def test_garbled_auth_token(app, client_nc):
    # garble token
    def augment_auth_token(tdata):
        del tdata["exp"]

    app.config["TESTING_AUGMENT_AUTH_TOKEN"] = augment_auth_token
    response = json_authenticate(client_nc)
    token = response.json["response"]["user"]["authentication_token"]
    verify_token(client_nc, token, status=401)


@pytest.mark.csrf(ignore_unauth=True, csrfprotect=True)
def test_token_auth_csrf(client):
    response = json_authenticate(client)
    token = response.json["response"]["user"]["authentication_token"]
    csrf_token = response.json["response"]["csrf_token"]
    headers = {"Authentication-Token": token}
    response = client.post("/token", headers=headers)
    assert b"The CSRF token is missing" in response.data

    # test JSON version
    response = client.post("/token", headers=headers, content_type="application/json")
    assert response.status_code == 400
    assert response.json["response"]["errors"][0] == "The CSRF token is missing."

    # now do it right
    headers["X-CSRF-Token"] = csrf_token
    response = client.post(
        "/token",
        headers=headers,
    )
    assert b"Token Authentication" in response.data


def test_http_auth(client, get_message):
    # browsers expect 401 response with WWW-Authenticate header - which will prompt
    # them to pop up a login form.
    response = client.get("/http", headers={})
    assert response.status_code == 401
    assert get_message("UNAUTHENTICATED") in response.data
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


def test_http_auth_no_authentication(client, get_message):
    response = client.get("/http", headers={})
    assert response.status_code == 401
    assert get_message("UNAUTHENTICATED") in response.data
    assert "WWW-Authenticate" in response.headers
    assert 'Basic realm="Login Required"' == response.headers["WWW-Authenticate"]


def test_http_auth_no_authentication_json(client, get_message):
    response = client.get("/http", headers={"accept": "application/json"})
    assert response.status_code == 401
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "UNAUTHENTICATED"
    )
    assert response.headers["Content-Type"] == "application/json"


def test_invalid_http_auth_invalid_username(client, get_message):
    response = client.get(
        "/http",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"bogus:bogus").decode("utf-8")
        },
    )
    assert get_message("UNAUTHENTICATED") in response.data
    assert "WWW-Authenticate" in response.headers
    assert 'Basic realm="Login Required"' == response.headers["WWW-Authenticate"]


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
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
        "UNAUTHENTICATED"
    )
    assert response.headers["Content-Type"] == "application/json"
    assert "WWW-Authenticate" in response.headers


def test_invalid_http_auth_bad_password(client, get_message):
    response = client.get(
        "/http",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"joe@lp.com:bogus").decode("utf-8")
        },
    )
    assert get_message("UNAUTHENTICATED") in response.data
    assert "WWW-Authenticate" in response.headers
    assert 'Basic realm="Login Required"' == response.headers["WWW-Authenticate"]


def test_custom_http_auth_realm(client, get_message):
    response = client.get(
        "/http_custom_realm",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"joe@lp.com:bogus").decode("utf-8")
        },
    )
    assert get_message("UNAUTHENTICATED") in response.data
    assert "WWW-Authenticate" in response.headers
    assert 'Basic realm="My Realm"' == response.headers["WWW-Authenticate"]


@pytest.mark.csrf(csrfprotect=True)
def test_http_auth_csrf(client, get_message):
    headers = {
        "Authorization": "Basic %s"
        % base64.b64encode(b"joe@lp.com:password").decode("utf-8")
    }
    response = client.post(
        "/http",
        headers=headers,
    )
    assert b"The CSRF token is missing" in response.data

    # test JSON version
    response = client.post("/http", headers=headers, content_type="application/json")
    assert response.status_code == 400
    assert response.json["response"]["errors"][0] == "The CSRF token is missing."

    # grab a csrf_token
    response = client.get("/login")
    csrf_token = get_form_input(response, "csrf_token")
    headers["X-CSRF-Token"] = csrf_token
    response = client.post(
        "/http",
        headers=headers,
    )
    assert b"HTTP Authentication" in response.data


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


def test_multi_auth_basic_invalid(client, get_message):
    response = client.get(
        "/multi_auth",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"bogus:bogus").decode("utf-8")
        },
    )
    assert get_message("UNAUTHENTICATED") in response.data
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


def test_session_loads_identity(app, client):
    @app.route("/identity_check")
    @auth_required("session")
    def id_check():
        if hasattr(g, "identity"):
            identity = g.identity
            assert hasattr(identity, "loader_called")
            assert identity.loader_called
        return "Success"

    json_authenticate(client)

    # add identity loader after authentication to only fire it for
    # session-authentication next `get` call
    @identity_loaded.connect_via(app)
    def identity_loaded_check(sender, identity):
        identity.loader_called = True

    response = client.get("/identity_check")
    assert b"Success" == response.data


def test_remember_token(client):
    response = authenticate(client, follow_redirects=False)
    client.delete_cookie("session")
    response = client.get("/profile")
    assert b"profile" in response.data


def test_request_loader_does_not_fail_with_invalid_token(client):
    client.set_cookie("remember_token")
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
    """If logged in, should get 'anonymous_user_required' redirect"""
    response = authenticate(client, follow_redirects=False)
    response = client.get("/register")
    assert "location" in response.headers
    assert "/anon_required" in response.location


@pytest.mark.registerable()
@pytest.mark.settings(post_login_view="/anon_required")
def test_anon_required_json(client, get_message):
    """If logged in, should get 'anonymous_user_required' response"""
    authenticate(client, follow_redirects=False)
    response = client.get("/register", headers={"Accept": "application/json"})
    assert response.status_code == 400
    assert response.json["response"]["errors"][0].encode("utf-8") == get_message(
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


def test_verifying_token_from_version_3x(app, client):
    """
    Check token generated with flask security 3.x, which has different form
    than token from version 4.0.0, can be verified
    """
    from .test_utils import get_auth_token_version_3x

    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        token = get_auth_token_version_3x(app, user)

    headers = {"Authentication-Token": token, "Accept": "application/json"}
    response = client.get("/profile", headers=headers)
    assert response.status_code == 200


def test_verifying_token_from_version_4x(app, client):
    from .test_utils import get_auth_token_version_4x

    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        token = get_auth_token_version_4x(app, user)

    headers = {"Authentication-Token": token, "Accept": "application/json"}
    response = client.get("/profile", headers=headers)
    assert response.status_code == 200


def test_change_token_uniquifier(app):
    pytest.importorskip("sqlalchemy")
    pytest.importorskip("flask_sqlalchemy")

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
    pytest.importorskip("sqlalchemy")
    pytest.importorskip("flask_sqlalchemy")

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


def test_token_query(app, client_nc):
    # Verify that when authenticating with auth token (and not session)
    # that there is just one DB query to get user.
    with capture_queries(app.security.datastore) as queries:
        response = json_authenticate(client_nc)
        assert len(queries) == 1
        token = response.json["response"]["user"]["authentication_token"]
        response = client_nc.get(
            "/token",
            headers={"Content-Type": "application/json", "Authentication-Token": token},
        )
        assert response.status_code == 200
    assert len(queries) == 2


def test_session_query(in_app_context):
    # Verify that when authenticating with auth token (but also sending session)
    # that there are 2 DB queries to get user.
    # This is since the session will load one - but auth_token_required needs to
    # verify that the TOKEN is valid (and it is possible that the user_id in the
    # session is different that the one in the token (huh?)
    myapp = in_app_context
    populate_data(myapp)
    myclient = myapp.test_client()

    response = json_authenticate(myclient)
    token = response.json["response"]["user"]["authentication_token"]
    with capture_queries(myapp.security.datastore) as queries:
        response = myclient.get(
            "/token",
            headers={"Content-Type": "application/json", "Authentication-Token": token},
        )
        assert response.status_code == 200
    assert len(queries) == 2


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


def test_auth_token_decorator(app, client_nc):
    """
    Test accessing endpoint decorated with auth_token_required
    when using token generated by flask security 3.x algorithm
    """
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        token = get_auth_token_version_3x(app, user)

    response = client_nc.get(
        "/token",
        headers={"Content-Type": "application/json", "Authentication-Token": token},
    )
    assert response.status_code == 200


@pytest.mark.filterwarnings("ignore:.*BACKWARDS_COMPAT_UNAUTHN:DeprecationWarning")
@pytest.mark.settings(backwards_compat_unauthn=True)
def test_unauthn_compat(client):
    response = client.get("/profile")
    assert response.status_code == 401
