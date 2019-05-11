# -*- coding: utf-8 -*-

"""Simple security for Flask apps."""

import io
import re
from setuptools import find_packages, setup

with io.open('README.rst', 'rt', encoding='utf8') as f:
    readme = f.read()

with io.open('flask_security/__init__.py', 'rt', encoding='utf8') as f:
    version = re.search(r'__version__ = \'(.*?)\'', f.read()).group(1)

tests_require = [
    'Flask-CLI>=0.4.0',
    'Flask-Mongoengine>=0.9.5',
    'Flask-Peewee>=0.6.5',
    'Flask-SQLAlchemy>=2.3',
    'bcrypt>=3.1.0',
    'check-manifest>=0.25',
    'coverage>=4.0',
    'isort>=4.2.2',
    'mock>=1.3.0',
    'mongoengine>=0.12.0',
    'mongomock>=3.14.0',
    'msgcheck>=2.9',
    'pony>=0.7.4',
    'psycopg2>=2.7.4',
    'pydocstyle>=1.0.0',
    'pymysql>=0.9.3',
    'pytest-cache>=1.0',
    'pytest-cov>=2.4.0',
    'pytest-flakes>=1.0.1',
    'pytest-mongo>=1.2.1',
    'pytest-pep8>=1.0.6',
    'pytest>=3.3.0',
    'sqlalchemy>=1.1.0',
    'sqlalchemy-utils>=0.33.0',
    'werkzeug>=0.12.2'
]

extras_require = {
    'docs': [
        'Flask-Sphinx-Themes>=1.0.1',
        'Sphinx>=1.4.2',
    ],
    'tests': tests_require,
}

extras_require['all'] = []
for reqs in extras_require.values():
    extras_require['all'].extend(reqs)

setup_requires = [
    'Babel>=1.3',
    'pytest-runner>=2.6.2',
    'twine',
    'wheel'
]

install_requires = [
    'Flask>=0.12',
    'Flask-Login>=0.3.0',
    'Flask-Mail>=0.9.1',
    'Flask-Principal>=0.4.0',
    'Flask-WTF>=0.13.1',
    'Flask-BabelEx>=0.9.3',
    'itsdangerous>=0.24',
    'passlib>=1.7',
]

packages = find_packages()

setup(
    name='Flask-Security-Too',
    version=version,
    description=__doc__,
    long_description=readme,
    keywords='flask security',
    license='MIT',
    author='Matt Wright',
    author_email='matt@nobien.net',
    maintainer='Chris Wagner',
    maintainer_email='jwag.wagner@gmail.com',
    url='https://github.com/jwag956/flask-security',
    packages=packages,
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    python_requires='>=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*',
    extras_require=extras_require,
    install_requires=install_requires,
    setup_requires=setup_requires,
    tests_require=tests_require,
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Development Status :: 4 - Beta',
    ],
)
