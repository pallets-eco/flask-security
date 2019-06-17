# -*- coding: utf-8 -*-

# DO NOT EDIT THIS FILE!
# This file has been autogenerated by dephell <3
# https://github.com/dephell/dephell

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import os.path

readme = ''
here = os.path.abspath(os.path.dirname(__file__))
readme_path = os.path.join(here, 'README.rst')
if os.path.exists(readme_path):
    with open(readme_path, 'rb') as stream:
        readme = stream.read().decode('utf8')

setup(
    long_description=readme,
    name='flask_security',
    version='3.2.0rc1',
    description=' Flask-Security is an opinionated Flask extension which adds basic\n  security and authentication features to your Flask apps quickly\n  and easily',
    python_requires='!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*,<4.0,>=2.7',
    project_urls={
        'repository': 'https://github.com/jwag956/flask-security',
        'documentation': 'https://flask-security-too.readthedocs.io'
    },
    author='Matt Wright',
    author_email='matt@nobien.net',
    maintainer='Chris Wagner',
    maintainer_email='jwag.wagner@gmail.com',
    license='MIT',
    classifiers=[
        'Environment :: Web Environment', 'Framework :: Flask',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent', 'Programming Language :: Python',
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
        'Development Status :: 4 - Beta'
    ],
    packages=['flask_security'],
    package_data={
        'flask_security': [
            'templates/security/*.html', 'templates/security/email/*.html',
            'templates/security/email/*.txt', 'translations/*.pot',
            'translations/*.txt', 'translations/ca_ES/LC_MESSAGES/*.po',
            'translations/da_DK/LC_MESSAGES/*.po',
            'translations/de_DE/LC_MESSAGES/*.po',
            'translations/es_ES/LC_MESSAGES/*.po',
            'translations/fr_FR/LC_MESSAGES/*.po',
            'translations/ja_JP/LC_MESSAGES/*.po',
            'translations/nl_NL/LC_MESSAGES/*.po',
            'translations/pt_BR/LC_MESSAGES/*.po',
            'translations/pt_PT/LC_MESSAGES/*.po',
            'translations/ru_RU/LC_MESSAGES/*.po',
            'translations/tr_TR/LC_MESSAGES/*.po',
            'translations/zh_Hans_CN/LC_MESSAGES/*.po'
        ]
    },
    install_requires=[
        'cachetools>=3.1.0', 'flask>=0.12', 'flask-babelex>=0.9.3',
        'flask-login>=0.4.1', 'flask-mail>=0.9.1', 'flask-principal>=0.4.0',
        'flask-wtf>=0.14.2', 'itsdangerous>=1.1.0', 'passlib>=1.7'
    ],
    extras_require={
        'dev': [
            'babel>=1.3', 'bcrypt>=3.1', 'check-manifest>=0.25',
            'coverage>=4.0', 'flake8>=3.7', 'flask-cli>=0.4.0',
            'flask-mongoengine>=0.9.5', 'flask-peewee>=3.0',
            'flask-sphinx-themes>=1.0.1', 'flask-sqlalchemy>=2.4',
            'isort>=4.2.2', 'mock>=1.3.0', 'mongoengine>=0.12.0',
            'mongomock>=3.16', 'msgcheck>=3.0', 'pony>=0.7.4',
            'pre-commit>=1.16', 'pydocstyle>=3.0.0', 'pyqrcode>=1.2',
            'pytest>=4.0.0', 'pytest-black>=0.3.7', 'pytest-cache>=1.0',
            'pytest-cov>=2.7.0', 'pytest-flake8>=1.0', 'pytest-runner>=2.6.2',
            'sphinx>=1.4.2', 'sphinx-issues>=1.2.0', 'sqlalchemy>=1.1.0',
            'tomlkit>=0.5.3', 'tox>=3.12'
        ],
        'tests': [
            'babel>=1.3', 'bcrypt>=3.1', 'check-manifest>=0.25',
            'coverage>=4.0', 'cryptography>=2.7', 'flask-cli>=0.4.0',
            'flask-mongoengine>=0.9.5', 'flask-peewee>=3.0',
            'flask-sphinx-themes>=1.0.1', 'flask-sqlalchemy>=2.4',
            'isort>=4.2.2', 'mock>=1.3.0', 'mongoengine>=0.12.0',
            'mongomock>=3.16', 'msgcheck>=3.0', 'pony>=0.7.4',
            'pydocstyle>=3.0.0', 'pyqrcode>=1.2', 'pytest>=4.0.0',
            'pytest-black>=0.3.7', 'pytest-cache>=1.0', 'pytest-cov>=2.7.0',
            'pytest-flake8>=1.0', 'pytest-runner>=2.6.2', 'sphinx>=1.4.2',
            'sphinx-issues>=1.2.0', 'sqlalchemy>=1.1.0', 'tomlkit>=0.5.3'
        ],
        'docs': [
            'flask-sphinx-themes>=1.0.1', 'sphinx>=1.4.2',
            'sphinx-issues>=1.2.0', 'tomlkit>=0.5.3'
        ]
    },
)
