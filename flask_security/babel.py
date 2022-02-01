"""
    flask_security.babel
    ~~~~~~~~~~~~~~~~~~~~

    I18N support for Flask-Security.

    :copyright: (c) 2019-2021 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    As of Flask-Babel 2.0.0 - it supports the Flask-BabelEx Domain extension - and it
    is maintained. (Flask-BabelEx is no longer maintained). So we start with that,
    then fall back to Flask-BabelEx, then fall back to a Null Domain
    (just as Flask-Admin).
"""

# flake8: noqa: F811

import typing as t

from flask import current_app
from .utils import config_value as cv


def has_babel_ext():
    # Has the application initialized the appropriate babel extension....
    return current_app and "babel" in current_app.extensions


_domain_cls = None


try:
    from flask_babel import Domain
    import babel.support

    _domain_cls = Domain
    _dir_keyword = "translation_directories"
except ImportError:  # pragma: no cover
    try:
        from flask_babelex import Domain
        import babel.support

        _domain_cls = Domain
        _dir_keyword = "dirname"
    except ImportError:
        # Fake up just enough
        class FsDomain:
            def __init__(self, app):
                pass

            @staticmethod
            def gettext(string, **variables):
                return string if not variables else string % variables

            @staticmethod
            def ngettext(singular, plural, num, **variables):
                variables.setdefault("num", num)
                return (singular if num == 1 else plural) % variables

        def is_lazy_string(obj):
            return False

        def make_lazy_string(__func, msg):
            return msg


if not t.TYPE_CHECKING:
    # mypy doesn't understand all this
    if _domain_cls:
        from babel.support import LazyProxy

        class FsDomain(_domain_cls):
            def __init__(self, app):
                super().__init__(
                    **{
                        "domain": cv("I18N_DOMAIN", app=app),
                        _dir_keyword: cv("I18N_DIRNAME", app=app),
                    }
                )

            def gettext(self, string, **variables):
                if not has_babel_ext():
                    return string if not variables else string % variables
                return super().gettext(string, **variables)

            def ngettext(self, singular, plural, num, **variables):  # pragma: no cover
                if not has_babel_ext():
                    variables.setdefault("num", num)
                    return (singular if num == 1 else plural) % variables
                return super().ngettext(singular, plural, num, **variables)

        def is_lazy_string(obj):
            """Checks if the given object is a lazy string."""
            return isinstance(obj, LazyProxy)

        def make_lazy_string(__func, msg):
            """Creates a lazy string by invoking func with args."""
            return LazyProxy(__func, msg, enable_cache=False)
