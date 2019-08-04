# -*- coding: utf-8 -*-
"""
    test_createable
    ~~~~~~~~~~~~~~~~~

    Createable tests
"""

import pytest
from flask import Flask
from utils import authenticate

from flask_security.core import UserMixin
from flask_security.signals import user_created

pytestmark = pytest.mark.createable()


def test_createable_flag(app, client, get_message):
    recorded = []

    @user_created.connect_via(app)
    def on_user_created(app, user, token):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        recorded.append(user)

    authenticate(client)

    # Test create view
    response = client.get("/create-user", follow_redirects=True)
    assert b"Create User" in response.data

    with app.mail.record_messages() as outbox:
        data = dict(email="dude@lp.com")
        response = client.post("/create-user", data=data)

    assert len(recorded) == 1
    assert len(outbox) == 1

    # Test creating user with an existing email
    data = dict(email="dude@lp.com")
    response = client.post("/create-user", data=data, follow_redirects=True)
    assert get_message("EMAIL_ALREADY_ASSOCIATED", email="dude@lp.com") in response.data

    # Test creating user with an existing email but case insensitive
    data = dict(email="Dude@lp.com")
    response = client.post("/create-user", data=data, follow_redirects=True)
    assert get_message("EMAIL_ALREADY_ASSOCIATED", email="Dude@lp.com") in response.data
