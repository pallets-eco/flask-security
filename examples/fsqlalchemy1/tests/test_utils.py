# Copyright 2019 by J. Christopher Wagner (jwag). All rights reserved.


class WrapApp:
    def __init__(self, app, user_cls=None, role_cls=None, mocks=None):
        """ Used to help create a app test fixture - with optionally passing in mocks
        """
        self.app = app
        self.user_cls = user_cls
        self.role_cls = role_cls
        self.test_client = app.test_client()
        self.mocks = mocks


def set_current_user(app, user):
    """ Set up so that when request is received,
        the token will cause 'user' to be made the current_user
    """

    def token_cb(request):
        if request.headers.get("Authentication-Token") == "token":
            return user
        return app.security.login_manager.anonymous_user()

    app.security.login_manager.request_loader(token_cb)


def create_fake_user(user_cls, email="unittest@me.com", userid=1, roles=None):
    """ Create fake user optionally with roles """
    user = user_cls()
    user.email = email
    user.id = userid
    user.password = "mypassword"
    user.active = True
    if roles:
        if isinstance(roles, list):
            user.roles = roles
        else:
            user.roles = [roles]
    return user


def create_fake_role(role_cls, name, permissions=None):
    if permissions:
        permissions = ",".join([p.strip() for p in permissions.split(",")])
    return role_cls(name=name, permissions=permissions)
