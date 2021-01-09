"""
    flask_security.babel
    ~~~~~~~~~~~~~~~~~~~~

    I18N support for Flask-Security.

    As of Flask-Babel 2.0.0 - it supports the Flask-BabelEx Domain extension - and it
    is maintained. (Flask-BabelEx is no longer maintained). So we start with that,
    then fall back to Flask-BabelEx, then fall back to a Null Domain
    (just as Flask-Admin).
"""

# flake8: noqa: F811

from wtforms.i18n import messages_path

from .utils import config_value as cv

_domain_cls = None
try:
    from flask_babel import Domain

    _domain_cls = Domain
    _dir_keyword = "translation_directories"
except ImportError:  # pragma: no cover
    try:
        from flask_babelex import Domain

        _domain_cls = Domain
        _dir_keyword = "dirname"
    except ImportError:
        # Fake up just enough
        class Domain:
            @staticmethod
            def gettext(string, **variables):
                return string % variables

            @staticmethod
            def ngettext(singular, plural, num, **variables):
                variables.setdefault("num", num)
                return (singular if num == 1 else plural) % variables

            @staticmethod
            def lazy_gettext(string, **variables):
                return Domain.gettext(string, **variables)

            class Translations:
                """ dummy Translations class for WTForms, no translation support """

                def gettext(self, string):
                    return string

                def ngettext(self, singular, plural, n):
                    return singular if n == 1 else plural

        def get_i18n_domain(app):
            return Domain()

        def have_babel():
            return False

        def is_lazy_string(obj):
            return False

        def make_lazy_string(__func, msg):
            return msg


if _domain_cls:
    # Have either Flask-Babel or Flask-BabelEx
    from babel.support import LazyProxy

    wtforms_domain = _domain_cls(messages_path(), domain="wtforms")

    def get_i18n_domain(app):
        kwargs = {
            _dir_keyword: cv("I18N_DIRNAME", app=app),
            "domain": cv("I18N_DOMAIN", app=app),
        }
        return _domain_cls(**kwargs)

    def have_babel():
        return True

    def is_lazy_string(obj):
        """Checks if the given object is a lazy string."""
        return isinstance(obj, LazyProxy)

    def make_lazy_string(__func, msg):
        """Creates a lazy string by invoking func with args."""
        return LazyProxy(__func, msg, enable_cache=False)

    class Translations:
        """Fixes WTForms translation support and uses wtforms translations."""

        def gettext(self, string):
            return wtforms_domain.gettext(string)

        def ngettext(self, singular, plural, n):
            return wtforms_domain.ngettext(singular, plural, n)
