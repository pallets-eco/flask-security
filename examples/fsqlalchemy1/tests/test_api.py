# Copyright 2019 by J. Christopher Wagner (jwag). All rights reserved.

from fsqlalchemy1.app import Blog

from .test_utils import create_fake_role, create_fake_user, set_current_user


def test_monitor_404(myapp):
    user = create_fake_user(
        myapp.user_cls, roles=create_fake_role(myapp.role_cls, "basic")
    )
    set_current_user(myapp.app, user)

    # This requires "monitor" role
    resp = myapp.test_client.get(
        "/ops",
        headers={myapp.app.config["SECURITY_TOKEN_AUTHENTICATION_HEADER"]: "token"},
    )
    assert resp.status_code == 403


def test_blog_write(myapp):
    user_role = create_fake_role(
        myapp.role_cls, "user", permissions="user-read, user-write"
    )
    user = create_fake_user(myapp.user_cls, roles=user_role)
    set_current_user(myapp.app, user)

    b1 = Blog(id=1, text="hi blog", user=user)
    myapp.mocks["blog_mock"].query.get.return_value = b1
    # This requires "user-write" permission
    resp = myapp.test_client.post(
        "/blog/1",
        headers={myapp.app.config["SECURITY_TOKEN_AUTHENTICATION_HEADER"]: "token"},
        data=dict({"text": "A new blog"}),
    )
    assert resp.status_code == 200
    assert b"Yes, unittest@me.com can update blog" == resp.data
