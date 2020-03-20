"""
Copyright 2020 by J. Christopher Wagner (jwag). All rights reserved.
:license: MIT, see LICENSE for more details.

"""

from datetime import datetime

from flask import Blueprint, abort, current_app, jsonify
from flask_security import auth_required

from app import SmsCaptureSender

api = Blueprint("api", __name__)


@api.route("/health", methods=["GET"])
@auth_required("session")
def health():
    return jsonify(secret="lush oranges", date=datetime.utcnow())


@api.route("/popmail", methods=["GET"])
def popmail():
    # This gets and pops the most recently sent email
    # Please please do not do this in your real application!
    mailer = current_app.extensions["mail"]
    sent = mailer.pop()
    if sent:
        return jsonify(mail=sent)
    abort(400)


@api.route("/popsms", methods=["GET"])
def popsms():
    # This gets and pops the most recently sent SMS
    # Please please do not do this in your real application!
    msg = SmsCaptureSender.pop()
    if msg:
        return jsonify(sms=msg)
    abort(400)
