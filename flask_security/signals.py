"""
flask_security.signals
~~~~~~~~~~~~~~~~~~~~~~

Flask-Security signals module

:copyright: (c) 2012 by Matt Wright.
:copyright: (c) 2019-2026 by J. Christopher Wagner (jwag).
:license: MIT, see LICENSE for more details.
"""

import blinker

signals = blinker.Namespace()

user_authenticated = signals.signal("user-authenticated", "a user has been authenticated")

user_unauthenticated = signals.signal("user-unauthenticated", "a user tried to access an unauthenticated resource")

user_failed_authn = signals.signal("user-failed-authn", "a user failed authentication (bad password, etc)")

user_registered = signals.signal("user-registered", "a new user has registered")

# For cases of RETURN_GENERIC_RESPONSES with existing email/username
user_not_registered = signals.signal("user-not-registered", "a user failed authentication (bad password, etc)")

user_confirmed = signals.signal("user-confirmed", "a user has confirmed their account")

confirm_instructions_sent = signals.signal("confirm-instructions-sent", "confirmation instructions have been sent to a user")

login_instructions_sent = signals.signal("login-instructions-sent", "login instructions have been sent to a user")

password_reset = signals.signal("password-reset", "a user's password has been reset")

password_changed = signals.signal("password-changed", "a user has changed their password")

reset_password_instructions_sent = signals.signal("password-reset-instructions-sent", "password reset instructions have been sent to a user")

tf_code_confirmed = signals.signal("tf-code-confirmed", "a two-factor authentication code has been confirmed")

tf_profile_changed = signals.signal("tf-profile-changed", "a two-factor authentication profile has been changed")

tf_security_token_sent = signals.signal("tf-security-token-sent", "a two-factor authentication security token has been sent")

tf_disabled = signals.signal("tf-disabled", "two-factor authentication has been disabled")

us_security_token_sent = signals.signal("us-security-token-sent", "a user Unified-Signin security token has been sent")

us_profile_changed = signals.signal("us-profile-changed", "a user Unified-Signin profile has been changed")

wan_registered = signals.signal("wan-registered", "a Passkey has been registered")

wan_deleted = signals.signal("wan-deleted", "a Passkey has been deleted")

change_email_instructions_sent = signals.signal("change-email-instructions-sent", "change email instructions have been sent to a user")

change_email_confirmed = signals.signal("change-email-confirmed", "a user has confirmed their email change")

username_recovery_email_sent = signals.signal("username-recovery-email-sent", "username recovery email has been sent to a user")

username_changed = signals.signal("username-changed", "a user has changed their username")
