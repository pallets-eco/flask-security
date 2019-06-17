.. _contributing:

===========================
Contributing
===========================


.. highlight:: console

Contributions are welcome.  If you would like add features or fix bugs,
this page should have all the information you need to make a contribution.

One source of history or ideas are the `bug reports`_.
There you can find ideas for requested features, or the remains of rejected
ideas.

.. _bug reports: https://github.com/jwag956/flask-security/issues




Getting the code
----------------

The code is hosted on a GitHub repo at
https://github.com/jwag956/flask-security.  To get a working environment, follow
these steps:

#.  (Optional, but recommended) Create a Python 3.6 (or greater) virtualenv to work in,
and activate it.  `Poetry <https://github.com/sdispater/poetry>`_,
`Dephell <https://github.com/dephell/dephell>`_ and `pre-commit <https://pre-commit.com/>`_
are recommended, but not strictly required.


#.  Fork the repo `Flask-Security <https://github.com/jwag956/flask-security>`_
        (look for the "Fork" button).

#.  Clone your fork locally::

        $ git clone https://github.com/<your-username>/flask-security

#. Create a branch for local development::

        $ git checkout -b name-of-your-bugfix-or-feature

#.  Change directory to flask_security::

        $ cd flask_security

#. (Optional) Activate your virtual environment

#. (Optional) Install the pre-commit hooks::

        $ pre-commit install

#.  Install the requirements::

        $ pip install -e .[tests]


Or if using Poetry, just install using::

        $ poetry install

#.  Develop the Feature/Bug Fix and edit


#.  Write Tests for your code in::

        tests/

#.  When done, run Black on the code::

        $ black .

#.  Also, make sure that Flake8 passes::

        $ flake8 .

#.  Test the code by running::

        $ pytest

Or if using Poetry::

        $ poetry run pytest

#. When the tests are successful, commit your changes
and push your branch to GitHub::

        $ git add .
        $ git commit -m "Your detailed description of your changes."
        $ git push origin name-of-your-bugfix-or-feature

#. Submit a pull request through the GitHub website.

#. Be sure that the CI tests and coverage checks pass.


