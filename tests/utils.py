# -*- coding: utf-8 -*-
"""
    utils
    ~~~~~

    Test utils

    :copyright: (c) 2019 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

from flask import Response as BaseResponse
from flask import json

try:
    from flask.json.tag import TaggedJSONSerializer
except Exception:
    from flask.sessions import TaggedJSONSerializer

from flask_security import Security
from flask_security.datastore import (
    SQLAlchemyUserDatastore,
    SQLAlchemySessionUserDatastore,
)
from flask_security.twofactor import generate_totp
from flask_security.utils import hash_password

from itsdangerous import URLSafeTimedSerializer
from werkzeug.http import parse_cookie

_missing = object


def authenticate(
    client, email="matt@lp.com", password="password", endpoint=None, **kwargs
):
    data = dict(email=email, password=password, remember="y")
    return client.post(endpoint or "/login", data=data, **kwargs)


def json_authenticate(client, email="matt@lp.com", password="password", endpoint=None):
    data = '{"email": "%s", "password": "%s"}' % (email, password)

    # Get auth token always
    ep = endpoint or "/login" + "?include_auth_token"
    return client.post(ep, content_type="application/json", data=data)


def verify_token(client_nc, token, status=None):
    # Use passed auth token in API that requires auth and verify status.
    # Pass in a client_nc to get valid results.
    response = client_nc.get(
        "/token",
        headers={"Content-Type": "application/json", "Authentication-Token": token},
    )
    if status:
        assert response.status_code == status
    else:
        assert b"Token Authentication" in response.data


def logout(client, endpoint=None, **kwargs):
    return client.get(endpoint or "/logout", **kwargs)


def json_logout(client, token, endpoint=None):
    return client.post(
        endpoint or "/logout",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authentication-Token": token,
        },
    )


def get_session(response):
    """ Return session cookie contents.
    This a base64 encoded json.
    Returns a dict
    """

    # Alas seems like if there are multiple set-cookie headers - we are on our own
    for index, h in enumerate(response.headers):
        if h[0] == "Set-Cookie":
            cookie = parse_cookie(response.headers[index][1])
            encoded_cookie = cookie.get("session", None)
            if encoded_cookie:
                serializer = URLSafeTimedSerializer(
                    "secret", serializer=TaggedJSONSerializer()
                )
                val = serializer.loads_unsafe(encoded_cookie)
                return val[1]


def check_xlation(app, locale):
    """ Return True if locale is loaded """
    with app.test_request_context():
        domain = app.security.i18n_domain
        xlations = domain.get_translations()
        return xlations and xlations._info.get("language", None) == locale


def create_roles(ds):
    roles = [
        ("admin", ["full-read", "full-write", "super"]),
        ("editor", ["full-read", "full-write"]),
        ("author", ["full-read", "my-write"]),
        ("simple", None),
    ]
    for role in roles:
        if hasattr(ds.role_model, "permissions") and role[1]:
            ds.create_role(name=role[0], permissions=",".join(role[1]))
        else:
            ds.create_role(name=role[0])
    ds.commit()


def create_users(app, ds, count=None):
    users = [
        ("matt@lp.com", "matt", "password", ["admin"], True, 123456, None),
        ("joe@lp.com", "joe", "password", ["editor"], True, 234567, None),
        ("dave@lp.com", "dave", "password", ["admin", "editor"], True, 345678, None),
        ("jill@lp.com", "jill", "password", ["author"], True, 456789, None),
        ("tiya@lp.com", "tiya", "password", [], False, 567890, None),
        ("gene@lp.com", "gene", "password", ["simple"], True, 889900, None),
        ("jess@lp.com", "jess", None, [], True, 678901, None),
        ("gal@lp.com", "gal", "password", ["admin"], True, 112233, "sms"),
        (
            "gal2@lp.com",
            "gal2",
            "password",
            ["admin"],
            True,
            223311,
            "google_authenticator",
        ),
        ("gal3@lp.com", "gal3", "password", ["admin"], True, 331122, "mail"),
    ]
    count = count or len(users)

    for u in users[:count]:
        pw = u[2]
        if pw is not None:
            pw = hash_password(pw)
        roles = [ds.find_or_create_role(rn) for rn in u[3]]
        ds.commit()
        totp_secret = None
        if app.config.get("SECURITY_TWO_FACTOR", None) and u[6]:
            totp_secret = generate_totp()
        user = ds.create_user(
            email=u[0],
            username=u[1],
            password=pw,
            active=u[4],
            security_number=u[5],
            tf_primary_method=u[6],
            tf_totp_secret=totp_secret,
        )
        ds.commit()
        for role in roles:
            ds.add_role_to_user(user, role)
        ds.commit()


def populate_data(app, user_count=None):
    ds = app.security.datastore
    with app.app_context():
        create_roles(ds)
        create_users(app, ds, user_count)


class Response(BaseResponse):  # pragma: no cover
    @property
    def jdata(self):
        rv = getattr(self, "_cached_jdata", _missing)
        if rv is not _missing:
            return rv
        try:
            self._cached_jdata = json.loads(self.data)
        except ValueError:
            raise Exception("Invalid JSON response")
        return self._cached_jdata


def init_app_with_options(app, datastore, **options):
    security_args = options.pop("security_args", {})
    app.config.update(**options)
    app.security = Security(app, datastore=datastore, **security_args)
    populate_data(app)


def get_num_queries(datastore):
    """ Return # of queries executed during test.
    return None if datastore doesn't support this.
    """
    if is_sqlalchemy(datastore):
        from flask_sqlalchemy import get_debug_queries

        return len(get_debug_queries())
    return None


def is_sqlalchemy(datastore):
    return isinstance(datastore, SQLAlchemyUserDatastore) and not isinstance(
        datastore, SQLAlchemySessionUserDatastore
    )
