#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from datetime import datetime
from flask import make_response, render_template, session, url_for, redirect, flash, abort
from flask_login import login_required, current_user

from . import main
from .forms import NameForm, EditProfileForm
from .. import db
from ..models import User
from ..email import send_email


@main.route('/', methods=['GET', 'POST'])
def index():
    form = NameForm()
    if form.validate_on_submit():
        if form.name.data == form.name_v.data:
            user = User.query.filter_by(username=form.name.data).first()
            if user is None:
                user = User(username=form.name.data)
                db.session.add(user)
                session['known'] = False
                if os.environ.get('FLASKY_ADMIN'):
                    send_email(os.environ.get('FLASKY_ADMIN'), '你有一个新用户', 'mail/new_user', user=user)
            else:
                session['known'] = True
            flash(u'欢迎回来,{}'.format(form.name.data), 'success')
            session['name'] = form.name.data
        else:
            flash(u'输入的名字不一致', 'danger')
            session['name'] = '陌生人'
        form.name.data = ''
        form.name_v.data = ''
        return redirect(url_for('.index'))
    return render_template('index.html', current_time=datetime.utcnow(), form=form, name=session.get('name'),
                           known=session.get('known', False))


# @main.route('/user/<name>')
# def user(name):
#     response = make_response(render_template('user.html', name=name))
#     return response


# 用户资料页面
@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    # if user is None:
    #     abort(404)
    return render_template('user.html', user=user)


# 编辑用户资料页面
@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash('您的资料已更新')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)
