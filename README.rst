Flask-Security
===================

.. image:: https://travis-ci.org/jwag956/flask-security.svg?branch=master
    :target: https://travis-ci.org/jwag956/flask-security

.. image:: https://coveralls.io/repos/github/jwag956/flask-security/badge.svg?branch=master
    :target: https://coveralls.io/github/jwag956/flask-security?branch=master

.. image:: https://img.shields.io/github/tag/jwag956/flask-security.svg
    :target: https://github.com/jwag956/flask-security/releases

.. image:: https://img.shields.io/pypi/dm/flask-security-too.svg
    :target: https://pypi.python.org/pypi/flask-security-too
    :alt: Downloads

.. image:: https://img.shields.io/github/license/jwag956/flask-security.svg
    :target: https://github.com/jwag956/flask-security/blob/master/LICENSE
    :alt: License

.. image:: https://readthedocs.org/projects/flask-security-too/badge/?version=latest
    :target: https://flask-security-too.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/python/black

Quickly add security features to your Flask application.

Notes on this repo
------------------
This is a independently maintained version of Flask-Security based on the 3.0.0
version of the `Original <https://github.com/mattupstate/flask-security>`_

Goals
+++++
* Regain momentum for this critical piece of the Flask eco-system. To that end the
  the plan is to put out small, frequent releases starting with pulling the simplest
  and most obvious changes that have already been vetted in the upstream version, as
  well as other pull requests. This was completed with the June 29 2019 3.2.0 release.
* Continue work to get Flask-Security to be usable from Single Page Applications,
  such as those built with Vue and Angular, that have no html forms. This is true as of the 3.3.0
  release.
* Use `OWASP <https://github.com/OWASP/ASVS>`_ to guide best practice and default configurations.
* Migrate to more modern paradigms such as using oauth2 and JWT for token acquisition.
* Be more opinionated and 'batteries' included by reducing reliance on abandoned projects and
  bundling in support for common use cases.
* Follow the `Pallets <https://github.com/pallets>`_ lead on supported versions, documentation
  standards and any other guidelines for extensions that they come up with.
* Any other great ideas.

Contributing
++++++++++++
Issues and pull requests are welcome. Other maintainers are also welcome. Unlike
the original Flask-Security - issue pull requests against the *master* branch.
Please consult these `contributing`_ guidelines.

.. _contributing: https://github.com/jwag956/flask-security/blob/master/CONTRIBUTING.rst

Installing
----------
Install and update using `pip <https://pip.pypa.io/en/stable/quickstart/>`_:

::

    pip install -U Flask-Security-Too


Resources
---------

- `Documentation <https://flask-security-too.readthedocs.io/>`_
- `Releases <https://pypi.org/project/Flask-Security-Too/>`_
- `Issue Tracker <https://github.com/jwag956/flask-security/issues>`_
- `Code <https://github.com/jwag956/flask-security/>`_
