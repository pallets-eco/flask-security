# -*- coding: utf-8 -*-
"""
    test_common
    ~~~~~~~~~~~

    Test common functionality

    :copyright: (c) 2019 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import base64
import json
import pytest

from utils import (
    authenticate,
    json_authenticate,
    get_num_queries,
    logout,
    populate_data,
    verify_token,
)

try:
    from cookielib import Cookie
except ImportError:
    from http.cookiejar import Cookie


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


def test_authenticate_with_invalid_next(client, get_message):
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http://google.com", data=data)
    assert get_message("INVALID_REDIRECT") in response.data


def test_authenticate_with_invalid_malformed_next(client, get_message):
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http:///google.com", data=data)
    assert get_message("INVALID_REDIRECT") in response.data


def test_authenticate_case_insensitive_email(app, client):
    response = authenticate(client, "MATT@lp.com", follow_redirects=True)
    assert b"Welcome matt@lp.com" in response.data


def test_authenticate_with_invalid_input(client, get_message):
    response = client.post(
        "/login", data="{}", headers={"Content-Type": "application/json"}
    )
    assert get_message("EMAIL_NOT_PROVIDED") in response.data


def test_login_form(client):
    response = client.post("/login", data={"email": "matt@lp.com"})
    assert b"matt@lp.com" in response.data


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
    """ Make sure that existing session doesn't work after
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
    """ Make sure that existing token doesn't work after
    user marked inactive
    """
    response = json_authenticate(client_nc)
    assert response.status_code == 200
    token = response.jdata["response"]["user"]["authentication_token"]
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
    assert response.jdata["meta"]["code"] == 200


def test_logout_with_next(client, get_message):
    authenticate(client)
    response = client.get("/logout?next=http://google.com")
    assert "google.com" not in response.location


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
def test_roles_accepted(client):
    # This specificaly tests that we can pass a URL for unauthorized_view.
    for user in ("matt@lp.com", "joe@lp.com"):
        authenticate(client, user)
        response = client.get("/admin_or_editor")
        assert b"Admin or Editor Page" in response.data
        logout(client)

    authenticate(client, "jill@lp.com")
    response = client.get("/admin_or_editor", follow_redirects=True)
    assert b"Unauthorized" in response.data


@pytest.mark.settings(unauthorized_view="unauthz")
def test_permissions_accepted(client):
    for user in ("matt@lp.com", "joe@lp.com"):
        authenticate(client, user)
        response = client.get("/admin_perm")
        assert b"Admin Page with full-write or super" in response.data
        logout(client)

    authenticate(client, "jill@lp.com")
    response = client.get("/admin_perm", follow_redirects=True)
    assert b"Unauthorized" in response.data


@pytest.mark.settings(unauthorized_view="unauthz")
def test_permissions_required(client):
    for user in ["matt@lp.com"]:
        authenticate(client, user)
        response = client.get("/admin_perm_required")
        assert b"Admin Page required" in response.data
        logout(client)

    authenticate(client, "joe@lp.com")
    response = client.get("/admin_perm_required", follow_redirects=True)
    assert b"Unauthorized" in response.data


@pytest.mark.settings(unauthorized_view="unauthz")
def test_unauthenticated_role_required(client, get_message):
    response = client.get("/admin", follow_redirects=True)
    assert get_message("UNAUTHORIZED") in response.data


@pytest.mark.settings(unauthorized_view="unauthz")
def test_multiple_role_required(client):
    for user in ("matt@lp.com", "joe@lp.com"):
        authenticate(client, user)
        response = client.get("/admin_and_editor", follow_redirects=True)
        assert b"Unauthorized" in response.data
        client.get("/logout")

    authenticate(client, "dave@lp.com")
    response = client.get("/admin_and_editor", follow_redirects=True)
    assert b"Admin and Editor Page" in response.data


def test_ok_json_auth(client):
    response = json_authenticate(client)
    assert response.jdata["meta"]["code"] == 200
    assert "authentication_token" in response.jdata["response"]["user"]


def test_invalid_json_auth(client):
    response = json_authenticate(client, password="junk")
    assert b'"code": 400' in response.data


def test_token_auth_via_querystring_valid_token(client):
    response = json_authenticate(client)
    token = response.jdata["response"]["user"]["authentication_token"]
    response = client.get("/token?auth_token=" + token)
    assert b"Token Authentication" in response.data


def test_token_auth_via_header_valid_token(client):
    response = json_authenticate(client)
    token = response.jdata["response"]["user"]["authentication_token"]
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
    response = client.get(
        "/http",
        headers={
            "Authorization": "Basic %s"
            % base64.b64encode(b"joe@lp.com:password").decode("utf-8")
        },
    )
    assert b"HTTP Authentication" in response.data


@pytest.mark.settings(USER_IDENTITY_ATTRIBUTES=("email", "username"))
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
    assert response.jdata["response"]["error"].encode("utf-8") == get_message(
        "UNAUTHENTICATED"
    )
    assert response.headers["Content-Type"] == "application/json"
    assert "WWW-Authenticate" in response.headers
    assert 'Basic realm="Login Required"' == response.headers["WWW-Authenticate"]


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
    response = client.get(
        "/http",
        headers={
            "accept": "application/json",
            "Authorization": "Basic %s"
            % base64.b64encode(b"bogus:bogus").decode("utf-8"),
        },
    )
    assert response.status_code == 401
    assert response.jdata["response"]["error"].encode("utf-8") == get_message(
        "UNAUTHENTICATED"
    )
    assert response.headers["Content-Type"] == "application/json"
    assert "WWW-Authenticate" in response.headers
    assert 'Basic realm="Login Required"' == response.headers["WWW-Authenticate"]


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
    # Default unauthn is to redirect
    assert response.status_code == 302


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
    print(response.headers)
    assert response.status_code == 401


def test_multi_auth_token(client):
    response = json_authenticate(client)
    token = response.jdata["response"]["user"]["authentication_token"]
    response = client.get("/multi_auth?auth_token=" + token)
    assert b"Token" in response.data


def test_multi_auth_session(client):
    authenticate(client)
    response = client.get("/multi_auth")
    assert b"Session" in response.data


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
    token = response.jdata["response"]["user"]["authentication_token"]
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
    assert response.jdata["response"]["user"]["id"] == "1"
    assert "last_update" in response.jdata["response"]["user"]

    response = client.get("/login", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.jdata["response"]["user"]["id"] == "1"
    assert "last_update" in response.jdata["response"]["user"]


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
    assert response.jdata["response"]["error"].encode("utf-8") == get_message(
        "ANONYMOUS_USER_REQUIRED"
    )


@pytest.mark.settings(security_hashing_schemes=["sha256_crypt"])
@pytest.mark.skip
def test_auth_token_speed(app, client_nc):
    # To run with old algorithm you have to comment out fs_uniquifier check in UserMixin
    import timeit

    response = json_authenticate(client_nc)
    token = response.jdata["response"]["user"]["authentication_token"]

    def time_get():
        rp = client_nc.get(
            "/login",
            data={},
            headers={"Content-Type": "application/json", "Authentication-Token": token},
        )
        assert rp.status_code == 200

    t = timeit.timeit(time_get, number=50)
    print("Time for 50 iterations: ", t)


def test_change_uniquifier(app, client_nc):
    # make sure that existing token no longer works once we change the uniquifier

    response = json_authenticate(client_nc)
    token = response.jdata["response"]["user"]["authentication_token"]
    verify_token(client_nc, token)

    # now change uniquifier
    # deactivate matt
    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        app.security.datastore.set_uniquifier(user)
        app.security.datastore.commit()

    verify_token(client_nc, token, status=401)

    # get new token and verify it works
    response = json_authenticate(client_nc)
    token = response.jdata["response"]["user"]["authentication_token"]
    verify_token(client_nc, token)


def test_token_query(in_app_context):
    # Verify that when authenticating with auth token (and not session)
    # that there is just one DB query to get user.
    app = in_app_context
    populate_data(app)
    client_nc = app.test_client(use_cookies=False)

    response = json_authenticate(client_nc)
    token = response.jdata["response"]["user"]["authentication_token"]
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
    token = response.jdata["response"]["user"]["authentication_token"]
    current_nqueries = get_num_queries(app.security.datastore)

    response = client.get(
        "/token",
        headers={"Content-Type": "application/json", "Authentication-Token": token},
    )
    assert response.status_code == 200
    end_nqueries = get_num_queries(app.security.datastore)
    assert current_nqueries is None or end_nqueries == (current_nqueries + 2)
