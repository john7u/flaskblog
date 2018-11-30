#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import render_template, redirect, request, url_for, flash
from . import auth
from ..models import User
from .form import LoginForm, RegistrationForm
from flask_login import login_required, login_user, logout_user, current_user
from .. import db
from ..email import send_email
import time


# 登陆路由
@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            """Flask_login会把用户访问的未授权url原地址保存在查询字符串的next参数中，
            这个参数可从request.args字典读取"""
            return redirect(request.args.get('next') or url_for('main.index'))
        flash(u'账号或密码错误')
    return render_template('auth/login.html', form=form)


# 退出路由
# 保护路由login_required作用是使登陆用户可访问
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash(u'你已退出登陆')
    return redirect(url_for('main.index'))


# 注册页面
@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, '请确认您的账号', 'auth/email/confirm',
                   user=user, token=token)
        flash('已向您的邮箱:{email}发送了一封确认邮件'.format(email=user.email))
        return redirect(url_for('.register'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
# @login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    elif current_user.confirm(token):
        flash('已经确认您的账户，谢谢')
        time.sleep(3)
        login_user(current_user)
        return redirect(url_for('main.index'))
    else:
        flash('确认连接无效或已过期')
        return redirect(url_for('.register'))
