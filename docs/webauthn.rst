.. _webauthn_topic:

WebAuthn
=========

WebAuthn/FIDO2 is a `W3C standard`_ that defines a cryptographic protocol between a
relying party (your Flask application) and an authenticator. In simple terms this allows connecting
your Flask application to a variety of authenticators including dedicated hardware (e.g. YubiKey) and
devices that have cryptographic capabilities (e.g. a mobile phone with fingerprint or face id).

This protocol is supported by all major browsers, however as of Spring 2022, few web application actually
support it, and those that do normally just support using a WebAuthn key as an additional, optional, second factor.

Note that a WebAuthn key can possibly satisfy a complete 2-factor authentication requirement - something you have
and something you are (think a mobile device with face-Id). Flask-Security supports this use case.

.. _W3C standard: https://www.w3.org/TR/webauthn-2/

Key Concepts
+++++++++++++

While the spec is quite complex - there are 2 important concepts to know. WebAuthn keys
can be classified as 'platform'/'cross-platform' and 'resident'/or not. If a key is a ``platform`` key
that means it is tied to a particular device. If you set up a second factor WebAuthn key that is a ``platform``
key you will ONLY BE ABLE TO AUTHENTICATE using that device. For that reason it is a best practice to make sure
there is at least one second-factor authentication method setup that is NOT platform specific (such as SMS, an authenticator app, etc.).

Flask-Security requires that when registering a WebAuthn key, the user must specify whether the key
will be used for first/primary authentication or for multi-factor/second authentication.

It should be noted the the current spec REQUIRES javascript to communicate from your front-end to the browser.
Flask-Security ships with the basic required JS (static/{webauthn.js,base64.js}).
An application should be able to simply wire those into their templates or javascript.


Configuration
++++++++++++++

As with many features in Flask-Security, configuration is a combination of config variables,
constructor parameters, and a sub-classable utility class. The WebAuthn spec offers a lot of
flexibility in supporting a wide range of authenticators. The default configuration is:

    - Allow a WebAuthn key to be used for first/primary authentication (:py:data:`SECURITY_WAN_ALLOW_AS_FIRST_FACTOR` = ``True``)
    - Allow a WebAuthn key to be used as a multi-factor (both first and secondary) if
      the key supports it (:py:data:`SECURITY_WAN_ALLOW_AS_MULTI_FACTOR` = ``True``)
    - Allow both 'first' and 'secondary' WebAuthn keys to be used for 'freshness' verification
      (:py:data:`SECURITY_WAN_ALLOW_AS_VERIFY` = ``True``)
    - Allow returning WebAuthn key names to un-authenticated users (:py:data:`SECURITY_WAN_ALLOW_USER_HINTS` = ``True``)
      Please see `this`_ portion of the WebAuthn spec for security implications.


The bundled :class:`.WebauthnUtil` class implements the following defaults:

    - The ``AuthenticatorSelectionCriteria`` is set to ``CROSS_PLATFORM`` for webauthn keys being
      registered for first/primary authentication.
    - The ``UserVerificationRequirement`` is set to ``DISCOURAGED`` for keys used for secondary
      authentication, and ``PREFERRED`` for keys used for first/primary or multi-factor.

.. _this: https://www.w3.org/TR/webauthn-2/#sctn-unprotected-account-detection
