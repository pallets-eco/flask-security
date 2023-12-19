"""
    flask_security.babel
    ~~~~~~~~~~~~~~~~~~~~

    I18N support for Flask-Security.

    :copyright: (c) 2019-2023 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    As of Flask-Babel 2.0.0 - it supports the Flask-BabelEx Domain extension - and it
    is maintained.  If that isn't installed fall back to a Null Domain
"""

# flake8: noqa: F811

from collections.abc import Iterable
import atexit
from contextlib import ExitStack
from importlib_resources import files, as_file

from flask import current_app
from .utils import config_value as cv


def has_babel_ext():
    # Has the application initialized the appropriate babel extension....
    return current_app and "babel" in current_app.extensions


try:
    from flask_babel import Domain, get_locale
    from babel.support import LazyProxy
    from babel.lists import format_list

    class FsDomain(Domain):
        def __init__(self, app):
            # By default, we use our packaged translations. However, we have to allow
            # for app to add translation directories or completely override ours.
            # Grabbing the packaged translations is a bit complex - so we use
            # the keyword 'builtin' to mean ours.
            cfdir = cv("I18N_DIRNAME", app=app)
            if cfdir == "builtin" or (
                isinstance(cfdir, Iterable) and "builtin" in cfdir
            ):
                fm = ExitStack()
                atexit.register(fm.close)
                ref = files("flask_security") / "translations"
                path = fm.enter_context(as_file(ref))
                if cfdir == "builtin":
                    dirs = [str(path)]
                else:
                    dirs = [d if d != "builtin" else str(path) for d in cfdir]
            else:
                dirs = cfdir
            super().__init__(
                **{
                    "domain": cv("I18N_DOMAIN", app=app),
                    "translation_directories": dirs,
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

        @staticmethod
        def format_list(lst, **kwargs):
            # This is a Babel method
            if not has_babel_ext():
                return ", ".join(lst)
            ll = get_locale()
            return format_list(lst, locale=get_locale(), **kwargs)

    def is_lazy_string(obj):
        """Checks if the given object is a lazy string."""
        return isinstance(obj, LazyProxy)

    def make_lazy_string(__func, msg):
        """Creates a lazy string by invoking func with args."""
        return LazyProxy(__func, msg, enable_cache=False)

except ImportError:  # pragma: no cover
    # Fake up just enough
    class FsDomain:  # type: ignore[no-redef]
        def __init__(self, app):
            pass

        @staticmethod
        def gettext(string, **variables):
            return string if not variables else string % variables

        @staticmethod
        def ngettext(singular, plural, num, **variables):
            variables.setdefault("num", num)
            return (singular if num == 1 else plural) % variables

        @staticmethod
        def format_list(lst, **kwargs):
            # This is a Babel method
            if not has_babel_ext():
                return ", ".join(lst)

    def is_lazy_string(obj):
        return False

    def make_lazy_string(__func, msg):
        return msg
