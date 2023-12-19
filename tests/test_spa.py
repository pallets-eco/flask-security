import pytest

from flask_security.utils import validate_redirect_url
from tests.test_utils import init_app_with_options


@pytest.mark.settings(redirect_validate_mode="regex")
def test_validate_redirect_for_spa(app, sqlalchemy_datastore):
    """
    Test various possible URLs that urlsplit() shows as relative but
    many browsers will interpret as absolute - and thus have a
    open-redirect vulnerability. Note this vulnerability only
    is viable if the application sets autocorrect_location_header = False
    """
    init_app_with_options(
        app, sqlalchemy_datastore, **{"SECURITY_REDIRECT_HOST": "localhost:4000"}
    )
    with app.test_request_context("http://localhost:5001/login"):
        assert validate_redirect_url("http://localhost:4000/login")
