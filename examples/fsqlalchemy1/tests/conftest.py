# Copyright 2019 by J. Christopher Wagner (jwag). All rights reserved.

try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock
import pytest


from .test_utils import WrapApp


@pytest.fixture
def myapp():
    """
    Create a wrapped flask app.
    This is used for unittests that want to mock out all
    underlying singletons (such as DBs).

    Assumes that app.security has been set.
    """

    from fsqlalchemy1.app import app, User, Role

    app.config["TESTING"] = True
    bmock = Mock()
    app.blog_cls = bmock
    return WrapApp(app, User, Role, mocks={"blog_mock": bmock})
