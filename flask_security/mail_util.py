"""
    flask_security.mail_util
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Utility class for managing outgoing emails

    :copyright: (c) 2020 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    While this default implementation uses FlaskMail - we want to make sure that
    FlaskMail isn't REQUIRED (if this implementation isn't used).
"""

from flask import current_app
from werkzeug.local import LocalProxy


_security = LocalProxy(lambda: current_app.extensions["security"])


class MailUtil:
    """
    To provide your own implementation, pass in the class as ``mail_util_cls``
    at init time.  Your class will be instantiated once as part of app initialization.

    .. versionadded:: 4.0.0
    """

    def __init__(self, app):
        """ Instantiate class.

        :param app: The Flask application being initialized.
        """
        pass

    def send_mail(
        self, template, subject, recipient, sender, body, html, user, **kwargs
    ):
        """Send an email via the Flask-Mail extension.

        :param template: the Template name. The message has already been rendered
            however this might be useful to differentiate why the email is being sent.
        :param subject: Email subject
        :param recipient: Email recipient
        :param sender: who to send email as (see :py:data:`SECURITY_EMAIL_SENDER`)
        :param body: the rendered body (text)
        :param html: the rendered body (html)
        :param user: the user model
        """

        from flask_mail import Message

        msg = Message(subject, sender=sender, recipients=[recipient])
        msg.body = body
        msg.html = html

        mail = current_app.extensions.get("mail")
        mail.send(msg)
