# -*- coding: utf-8 -*-
"""
    utils
    ~~~~~

    Test utils
"""

from flask import Response as BaseResponse
from flask import json

from flask_security import Security
from flask_security.datastore import SQLAlchemyUserDatastore,\
    SQLAlchemySessionUserDatastore
from flask_security.utils import encrypt_password

_missing = object


def authenticate(
        client,
        email="matt@lp.com",
        password="password",
        endpoint=None,
        **kwargs):
    data = dict(email=email, password=password, remember='y')
    return client.post(endpoint or '/login', data=data, **kwargs)


def json_authenticate(
        client,
        email="matt@lp.com",
        password="password",
        endpoint=None):
    data = '{"email": "%s", "password": "%s"}' % (email, password)
    return client.post(
        endpoint or '/login',
        content_type="application/json",
        data=data)


def logout(client, endpoint=None, **kwargs):
    return client.get(endpoint or '/logout', **kwargs)


def create_roles(ds):
    for role in ('admin', 'editor', 'author'):
        ds.create_role(name=role)
    ds.commit()


def create_users(ds, count=None):
    users = [('matt@lp.com', 'matt', 'password', ['admin'], True, 123456),
             ('joe@lp.com', 'joe', 'password', ['editor'], True, 234567),
             ('dave@lp.com', 'dave', 'password', ['admin', 'editor'], True,
              345678),
             ('jill@lp.com', 'jill', 'password', ['author'], True, 456789),
             ('tiya@lp.com', 'tiya', 'password', [], False, 567890),
             ('gene@lp.com', 'gene', 'password', [], True, 889900),
             ('jess@lp.com', 'jess', None, [], True, 678901)]
    count = count or len(users)

    for u in users[:count]:
        pw = u[2]
        if pw is not None:
            pw = encrypt_password(pw)
        roles = [ds.find_or_create_role(rn) for rn in u[3]]
        ds.commit()
        user = ds.create_user(
            email=u[0],
            username=u[1],
            password=pw,
            active=u[4],
            security_number=u[5])
        ds.commit()
        for role in roles:
            ds.add_role_to_user(user, role)
        ds.commit()


def populate_data(app, user_count=None):
    ds = app.security.datastore
    with app.app_context():
        create_roles(ds)
        create_users(ds, user_count)


class Response(BaseResponse):  # pragma: no cover

    @property
    def jdata(self):
        rv = getattr(self, '_cached_jdata', _missing)
        if rv is not _missing:
            return rv
        try:
            self._cached_jdata = json.loads(self.data)
        except ValueError:
            raise Exception('Invalid JSON response')
        return self._cached_jdata


def init_app_with_options(app, datastore, **options):
    security_args = options.pop('security_args', {})
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
    return isinstance(datastore, SQLAlchemyUserDatastore) and\
            not isinstance(datastore, SQLAlchemySessionUserDatastore)
