"""Simple security for Flask apps."""

import re
from setuptools import find_packages, setup

with open("README.rst", encoding="utf8") as f:
    readme = f.read()

with open("flask_security/__init__.py", encoding="utf8") as f:
    version = re.search(r'__version__ = "(.*?)"', f.read()).group(1)

install_requires = [
    "Flask>=1.1.1",
    "Flask-Login>=0.4.1",
    "Flask-Principal>=0.4.0",
    "Flask-WTF>=0.14.3",
    "email-validator>=1.1.1",
    "itsdangerous>=1.1.0",
    "passlib>=1.7.2",
    "blinker>=1.4",
]

packages = find_packages(exclude=["tests"])

setup(
    name="Flask-Security-Too",
    version=version,
    description=__doc__,
    long_description=readme,
    keywords="flask security",
    license="MIT",
    author="Matt Wright & Chris Wagner",
    author_email="jwag.wagner+github@gmail.com",
    url="https://github.com/Flask-Middleware/flask-security",
    project_urls={
        "Documentation": "https://flask-security-too.readthedocs.io",
        "Releases": "https://pypi.org/project/Flask-Security-Too/",
        "Code": "https://github.com/Flask-Middleware/flask-security",
        "Issue tracker": "https://github.com/Flask-Middleware/flask-security/issues",
    },
    packages=packages,
    zip_safe=False,
    include_package_data=True,
    platforms="any",
    python_requires=">=3.6",
    install_requires=install_requires,
    classifiers=[
        "Environment :: Web Environment",
        "Framework :: Flask",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Development Status :: 4 - Beta",
    ],
)
