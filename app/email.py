#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import create_app, mail
from flask import render_template
from flask_mail import Message
import os
from threading import Thread
app = create_app(os.getenv('FLASK_CONFIG') or 'default')


class EmailHandler(Thread):
    def __init__(self, a, msg):
        super(EmailHandler, self).__init__()
        self.app = a
        self.msg = msg

    def send_sync_email(self):
        with self.app.app_context:
            mail.send(self.msg)


def send_email(to, subject, template, **kwargs):
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,
                  sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    EmailHandler(app, msg).start()
