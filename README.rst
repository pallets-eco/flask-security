Flask-Security
===================

.. image:: https://github.com/pallets-eco/flask-security/workflows/tests/badge.svg?branch=main&event=push
    :target: https://github.com/pallets-eco/flask-security

.. image:: https://codecov.io/gh/pallets-eco/flask-security/graph/badge.svg?token=ZYS0AST5M3
    :target: https://codecov.io/gh/pallets-eco/flask-security
    :alt: Coverage!

.. image:: https://img.shields.io/github/tag/pallets-eco/flask-security.svg
    :target: https://github.com/pallets-eco/flask-security/releases

.. image:: https://img.shields.io/pypi/dm/flask-security.svg
    :target: https://pypi.python.org/pypi/flask-security
    :alt: Downloads

.. image:: https://img.shields.io/pypi/dm/flask-security-too.svg
    :target: https://pypi.python.org/pypi/flask-security-too
    :alt: Downloads

.. image:: https://img.shields.io/github/license/pallets-eco/flask-security.svg
    :target: https://github.com/pallets-eco/flask-security/blob/main/LICENSE
    :alt: License

.. image:: https://readthedocs.org/projects/flask-security/badge/?version=latest
    :target: https://flask-security.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/python/black

.. image:: https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white
    :target: https://github.com/pre-commit/pre-commit
    :alt: pre-commit

Quickly add security features to your Flask application.

Notes on this repo
------------------
As of 7/30/2024, the independent fork Flask-Security-Too replaced the archived
Flask-Security repo (now called Flask-Security-3.0). This repo is published at PyPI at
both Flask-Security and Flask-Security-Too.

Flask-Security-Too was a fork from the 3.0.0
version of the `Original <https://github.com/mattupstate/flask-security>`_

Pallets Community Ecosystem
----------------------------

This project is part of the Pallets Community Ecosystem. Pallets is the open
source organization that maintains Flask; Pallets-Eco enables community
maintenance of related projects. If you are interested in helping maintain
this project, please reach out on `the Pallets Discord server <https://discord.gg/pallets>`.

Goals
+++++

* Use `OWASP <https://github.com/OWASP/ASVS>`_ to guide best practice and default configurations.
* Be more opinionated and 'batteries' included by reducing reliance on abandoned projects and
  bundling in support for common use cases.
* Follow the `Pallets <https://github.com/pallets>`_ lead on supported versions, documentation
  standards and any other guidelines for extensions that they come up with.
* Continue to add newer authentication/authorization standards:
    * 'Social Auth' integrated (using authlib) (5.1)
    * WebAuthn support (5.0)
    * Two-Factor recovery codes (5.0)
    * First-class support for username as identity (4.1)
    * Support for freshness decorator to ensure sensitive operations have new authentication (4.0)
    * Support for email normalization and validation (4.0)
    * Unified signin (username, phone, passwordless) feature (3.4)


Contributing
++++++++++++
Issues and pull requests are welcome. Other maintainers are also welcome.
Please consult these `contributing`_ guidelines.

.. _contributing: https://github.com/pallets-eco/flask-security/blob/main/CONTRIBUTING.rst

Installing
----------
Install and update using `pip <https://pip.pypa.io/en/stable/quickstart/>`_:

::

    pip install -U Flask-Security


Resources
---------

- `Documentation <https://flask-security.readthedocs.io/>`_
- `Releases <https://pypi.org/project/Flask-Security/>`_
- `Issue Tracker <https://github.com/pallets-eco/flask-security/issues>`_
- `Code <https://github.com/pallets-eco/flask-security/>`_
