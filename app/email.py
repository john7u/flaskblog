#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import create_app, mail
from flask import render_template
from flask_mail import Message
import os
from threading import Thread
app = create_app(os.getenv('FLASK_CONFIG') or 'default')


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(to, subject, template, **kwargs):
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,
                  sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr
