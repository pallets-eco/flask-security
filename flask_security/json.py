"""
    Flask-Security JSON extensions.

    :copyright: (c) 2022-2024 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    Pieces of this code liberally copied from flask-mongoengine.
"""


def _use_provider(superclass):
    """Flask 2.2 onwards - customize JSONProvider"""

    class FSJsonProvider(superclass):
        @staticmethod
        def default(obj):
            from .babel import is_lazy_string

            if is_lazy_string(obj):
                return str(obj)
            return super(FSJsonProvider, FSJsonProvider).default(obj)

    return FSJsonProvider


def setup_json(app, bp=None):
    # Called at init_app time.
    # Flask >= 2.2
    app.json_provider_class = _use_provider(app.json_provider_class)
    app.json = app.json_provider_class(app)
