# -*- coding: utf-8 -*-
"""
    flask_security.cache
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security token cache module

    :copyright: (c) 2019.
    :license: MIT, see LICENSE for more details.
"""

from .utils import config_value


class VerifyHashCache:
    """Cache handler to make it quick password check by bypassing
    already checked passwords against exact same couple of token/password.
    This cache handler is more efficient on small apps that
    run on few processes as cache is only shared between threads."""

    def __init__(self):
        ttl = config_value("VERIFY_HASH_CACHE_TTL", default=(60 * 5))
        max_size = config_value("VERIFY_HASH_CACHE_MAX_SIZE", default=500)

        try:
            from cachetools import TTLCache

            self._cache = TTLCache(max_size, ttl)
        except ImportError:
            # this should have been checked at app init.
            raise

    def has_verify_hash_cache(self, user):
        """Check given user id is in cache."""
        return self._cache.get(user.id)

    def set_cache(self, user):
        """When a password is checked, then result is put in cache."""
        self._cache[user.id] = True

    def clear(self):
        """Clear cache"""
        self._cache.clear()
