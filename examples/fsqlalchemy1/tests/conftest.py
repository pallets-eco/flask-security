# Copyright 2019 by J. Christopher Wagner (jwag). All rights reserved.
import pytest


@pytest.fixture
def myapp():
    """
    Create a wrapped flask app.
    This is used for unittests that want to mock out all
    underlying singletons (e.g. blog).

    Assumes that app.security has been set.
    """

    from fsqlalchemy1.app import create_app

    app = create_app()
    app.config["TESTING"] = True
    return app
