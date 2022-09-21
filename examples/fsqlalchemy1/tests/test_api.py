# Copyright 2019-2022 by J. Christopher Wagner (jwag). All rights reserved.

from fsqlalchemy1.app import Blog

from .test_utils import set_current_user


def test_monitor_404(myapp):
    ds = myapp.security.datastore
    with myapp.app_context():
        ds.db.create_all()

        r1 = ds.create_role(name="basic")
        ds.create_user(email="unittest@me.com", password="password", roles=[r1])
        ds.commit()

    set_current_user(myapp, ds, "unittest@me.com")

    # This requires "monitor" role
    resp = myapp.test_client().get(
        "/ops",
        headers={myapp.config["SECURITY_TOKEN_AUTHENTICATION_HEADER"]: "token"},
    )
    assert resp.status_code == 403


def test_blog_write(myapp):
    ds = myapp.security.datastore
    with myapp.app_context():
        ds.db.create_all()

        r1 = ds.create_role(name="user", permissions={"user-read", "user-write"})
        user = ds.create_user(email="unittest@me.com", password="password", roles=[r1])

        b1 = Blog(id=1, text="hi blog", user=user)
        ds.put(b1)
        ds.commit()

    set_current_user(myapp, ds, "unittest@me.com")

    # This requires "user-write" permission
    resp = myapp.test_client().post(
        "/blog/1",
        headers={myapp.config["SECURITY_TOKEN_AUTHENTICATION_HEADER"]: "token"},
        data=dict({"text": "A new blog"}),
    )
    assert resp.status_code == 200
    assert b"Yes, unittest@me.com can update blog" == resp.data
