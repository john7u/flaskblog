#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import render_template, redirect, request, url_for, flash
from . import auth
from ..models import User
from .form import LoginForm, RegistrationForm
from flask_login import login_required, login_user, logout_user
from .. import db


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
        flash('完成注册')
        return redirect(url_for('.login'))
    return render_template('auth/register.html', form=form)
