"""
    flask_security.signals
    ~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security signals module

    :copyright: (c) 2012 by Matt Wright.
    :copyright: (c) 2019-2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.
"""

import blinker

signals = blinker.Namespace()

user_authenticated = signals.signal("user-authenticated")

user_registered = signals.signal("user-registered")

user_confirmed = signals.signal("user-confirmed")

confirm_instructions_sent = signals.signal("confirm-instructions-sent")

login_instructions_sent = signals.signal("login-instructions-sent")

password_reset = signals.signal("password-reset")

password_changed = signals.signal("password-changed")

reset_password_instructions_sent = signals.signal("password-reset-instructions-sent")

tf_code_confirmed = signals.signal("tf-code-confirmed")

tf_profile_changed = signals.signal("tf-profile-changed")

tf_security_token_sent = signals.signal("tf-security-token-sent")

tf_disabled = signals.signal("tf-disabled")

us_security_token_sent = signals.signal("us-security-token-sent")

us_profile_changed = signals.signal("us-profile-changed")
