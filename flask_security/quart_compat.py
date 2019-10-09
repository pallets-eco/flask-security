# -*- coding: utf-8 -*-
"""
    flask_security.quart_compat
    ~~~~~~~~~~~~~~~~~~~~

    Flask-Security quart compatibility modiles

    :copyright: (c) 2019 by Shinon.
    :license: MIT, see LICENSE for more details.

    This modules tests whether we are using quart or not
    we can test if the name of the imported flask is: quart.flask_patch
"""
import flask

if flask.__name__ == "quart.flask_patch":
    is_quart = True
else:
    is_quart = False


def get_quart_status():
    """
    Tests if we are using Quart Patched Flask or Vanilla Flask.
    :return: boolean value determining if it is quart patched flask or not
    """
    return is_quart
