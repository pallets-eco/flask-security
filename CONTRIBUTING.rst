.. _contributing:

===========================
Contributing
===========================


.. highlight:: console

Contributions are welcome.  If you would like add features or fix bugs,
please review the information below.

One source of history or ideas are the `bug reports`_.
There you can find ideas for requested features, or the remains of rejected
ideas.

If you have a 'big idea' - please file an issue first so it can be discussed
prior to you spending a lot of time developing. New features need to be generally
useful - if your feature has limited applicability, consider making a small
change that ENABLES your feature, rather than trying to get the entire feature
into Flask-Security.

.. _bug reports: https://github.com/Flask-Middleware/flask-security/issues


Checklist
---------

    * All new code and bug fixes need unit tests
    * If you change/add to the external API be sure to update docs/openapi.yaml
    * Additions to configuration variables and/or messages must be documented
    * Make sure any new public API methods have good docstrings, are picked up by
      the api.rst document, and are exposed in __init__.py if appropriate.
    * Add appropriate info to CHANGES.rst


Getting the code
----------------

The code is hosted on a GitHub repo at
https://github.com/Flask-Middleware/flask-security.  To get a working environment, follow
these steps:

  #. (Optional, but recommended) Create a Python 3.6 (or greater) virtualenv to work in,
     and activate it.

  #. Fork the repo `Flask-Security <https://github.com/Flask-Middleware/flask-security>`_
      (look for the "Fork" button).

  #. Clone your fork locally::

        $ git clone https://github.com/<your-username>/flask-security

  #. Change directory to flask_security::

        $ cd flask_security

  #. Install the requirements::

        $ pip install -r requirements/dev.txt

  #. Install pre-commit hooks::

        $ pre-commit install

  #. Create a branch for local development::

        $ git checkout -b name-of-your-bugfix-or-feature

  #. Develop the Feature/Bug Fix and edit

  #. Write Tests for your code in::

        tests/

  #. When done, verify unit tests, syntax etc. all pass::

        $ pip install -r requirements/tests.txt
        $ sphinx-build docs docs/_build/html
        $ tox -e compile_catalog
        $ pytest tests
        $ pre-commit run --all-files

  #. Use tox::

        $ tox  # run everything CI does
        $ tox -e py38-low  # make sure works with older dependencies
        $ tox -e style  # run pre-commit/style checks

  #. When the tests are successful, commit your changes
     and push your branch to GitHub::

        $ git add .
        $ git commit -m "Your detailed description of your changes."
        $ git push origin name-of-your-bugfix-or-feature

  #. Submit a pull request through the GitHub website.

  #. Be sure that the CI tests and coverage checks pass.

Updating the Swagger API document
----------------------------------
When making changes to the external API, you need to update the openapi.yaml
formal specification. To do this - install the swagger editor locally::

    $ npm -g install swagger-editor-dist http-server

Then in a browser navigate to::

    file:///usr/local/lib/node_modules/swagger-editor-dist/index.html#


Edit - it is a WYSIWYG editor and will show you errors. Once you save (as yaml) you
need to look at what it will render as::

    $ sphinx-build docs docs/_build/html
    $ http-server -p 8081

Then in your browser navigate to::

    http://localhost:8081/docs/_build/html/index.html
    or
    http://localhost:8081/docs/_build/html/_static/openapi_view.html


Please note that changing ``openapi.yaml`` won't re-trigger a docs build - so you might
have to manually delete ``docs/_build``.

Updating Translations
---------------------
If you change any translatable strings (such as new messages, modified forms, etc.)
you need to re-generate the translations::

    $ tox -e extract_messages
    $ tox -e update_catalog
    $ tox -e compile_catalog

Testing
-------
Unit tests are critical since Flask-Security is a piece of middleware. They also
help other contributors understand any subtleties in the code and edge conditions that
need to be handled.

Datastore
+++++++++
By default the unit tests use an in-memory sqlite DB to test datastores (except for
MongoDatastore which uses mongomock). While this is sufficient for most changes, changes
to the datastore layer require testing against a real DB (the CI tests test against
postgres). It is easy to run the unit tests against a real DB instance. First
of course install and start the DB locally then::

  # For postgres
  pytest --realdburl postgresql://<user>@localhost/
  # For mysql
  pytest --realdburl "mysql+pymysql://root:<password>@localhost/"
  # For mongodb
  pytest --realmongodburl "localhost"

Views
+++++
Much of Flask-Security is concerned with form-based views. These can be difficult to test
especially translations etc. In the tests directory is a stand-alone Flask application
``view_scaffold.py`` that can be run and you can point your browser to it and walk
through the various views.
