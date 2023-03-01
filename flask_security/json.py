"""
    Flask-Security JSON extensions.

    :copyright: (c) 2022-2023 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    Pieces of this code liberally copied from flask-mongoengine.
"""
from flask import __version__ as flask_version
from pkg_resources import parse_version


def use_json_provider() -> bool:
    """Split Flask before 2.2.0 and after, to use/not use JSON provider approach."""
    return parse_version(flask_version) >= parse_version("2.2.0")


def _use_encoder(superclass):  # pragma: no cover
    """Flask < 2.2"""

    class FsJsonEncoder(superclass):
        """Flask-Security JSON encoder.
        Extends Flask's JSONencoder to handle lazy-text.
        """

        def default(self, obj):
            from .babel import is_lazy_string

            if is_lazy_string(obj):
                return str(obj)
            else:
                return super().default(obj)

    return FsJsonEncoder


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
    if use_json_provider():
        app.json_provider_class = _use_provider(app.json_provider_class)
        app.json = app.json_provider_class(app)
        # a bit if a hack - if a package (e.g. flask-mongoengine) hasn't
        # converted yet - they might use json_encoder. This ONLY applies
        # to this specific version of Flask that happens to use _json_encoder to
        # signal if any app/extension has registered an old style encoder.
        # (app.json_encoder is always set)
        # (If they do, then Flask 2.2.x won't use json_provider at all)
        # Of course if they do this AFTER we're initialized all bets are off.
        if parse_version(flask_version) >= parse_version("2.2.0"):
            if getattr(app, "_json_encoder", None):
                app.json_encoder = _use_encoder(app.json_encoder)

    elif bp:  # pragma: no cover
        bp.json_encoder = _use_encoder(app.json_encoder)
