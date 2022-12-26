"""
    flask_security.mail_util
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Utility class providing methods for validating, normalizing and sending emails.

    :copyright: (c) 2020-2022 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    While this default implementation uses Flask-Mailman - we want to make sure that
    Flask-Mailman isn't REQUIRED (if this implementation isn't used).
"""
import typing as t

import email_validator
from flask import current_app

from .utils import config_value

if t.TYPE_CHECKING:  # pragma: no cover
    import flask


class MailUtil:
    """
    Utility class providing methods for validating, normalizing and sending emails.

    This default class uses the email_validator package to handle validation and
    normalization, and the flask_mailman package (if initialized) to send emails.

    To provide your own implementation, pass in the class as ``mail_util_cls``
    at init time.  Your class will be instantiated once as part of app initialization.

    .. versionadded:: 4.0.0
    """

    def __init__(self, app: "flask.Flask"):
        """Instantiate class.

        :param app: The Flask application being initialized.
        """
        pass

    def send_mail(
        self,
        template: str,
        subject: str,
        recipient: str,
        sender: t.Union[str, tuple],
        body: str,
        html: t.Optional[str],
        **kwargs: t.Any,
    ) -> None:
        """Send an email via the Flask-Mailman or Flask-Mail or other mail extension.

        :param template: the Template name. The message has already been rendered
            however this might be useful to differentiate why the email is being sent.
        :param subject: Email subject
        :param recipient: Email recipient
        :param sender: who to send email as (see :py:data:`SECURITY_EMAIL_SENDER`)
        :param body: the rendered body (text)
        :param html: the rendered body (html)
        :param kwargs: the entire context

        It is possible that sender is a lazy_string for localization (unlikely but..)
        so we cast to str() here to force localization.
        """

        if current_app.extensions.get("mailman", None):
            from flask_mailman import EmailMultiAlternatives, Mail

            # Flask-Mailman doesn't appear to take a tuple - a bug has been filed
            # but not sure they will fix it (parts of Flask-Mailman work - but not
            # the actual email headers).
            if isinstance(sender, tuple) and len(sender) == 2:
                #  sender = (str(sender[0]), str(sender[1]))
                sender = f"{str(sender[0])} <{str(sender[1])}>"
            else:
                sender = str(sender)

            mail: Mail = current_app.extensions.get("mailman")
            with mail.get_connection() as connection:
                msg = EmailMultiAlternatives(
                    subject,
                    body=body,
                    from_email=sender,
                    to=[recipient],
                    connection=connection,
                )
                if html:
                    msg.attach_alternative(html, "text/html")
                msg.send()

        elif current_app.extensions.get("mail", None):  # pragma: no cover
            from flask_mail import Message

            # In Flask-Mail, sender can be a two element tuple -- (name, address)
            if isinstance(sender, tuple) and len(sender) == 2:
                sender = (str(sender[0]), str(sender[1]))
            else:
                sender = str(sender)
            msg = Message(subject, sender=sender, recipients=[recipient])
            msg.body = body
            msg.html = html

            mail = current_app.extensions.get("mail")
            mail.send(msg)  # type: ignore

        else:  # pragma: no cover
            raise ValueError("No email extension configured")

    def normalize(self, email: str) -> str:
        """
        Given an input email - return a normalized version.
        Must be called in app context and uses :py:data:`SECURITY_EMAIL_VALIDATOR_ARGS`
        config variable to pass any relevant arguments to
        email_validator.validate_email() method.

        Will throw email_validator.EmailNotValidError if email isn't even valid.
        """
        validator_args = config_value("EMAIL_VALIDATOR_ARGS") or {}
        valid = email_validator.validate_email(email, **validator_args)
        return valid.email

    def validate(self, email: str) -> str:
        """
        Validate the given email.
        If valid, the normalized version is returned.

        ValueError is thrown if not valid.
        """

        validator_args = config_value("EMAIL_VALIDATOR_ARGS") or {}
        valid = email_validator.validate_email(email, **validator_args)
        return valid.email
