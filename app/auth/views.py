#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import render_template, redirect, request, url_for, flash
from . import auth
from ..models import User
from .form import LoginForm, RegistrationForm, \
    BeforeResetpswd, ChangePassword, AfterResetpswd, ChangeMail
from flask_login import login_required, login_user, logout_user, current_user
from .. import db
from .. import email
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
        flash(u'账号或密码错误', 'warning')
    return render_template('auth/login.html', form=form)


# 退出路由
# 保护路由login_required作用是使登陆用户可访问
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash(u'你已退出登陆', 'info')
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
        email.send_email(user.email, '确认您的账号', 'auth/email/confirm',
                         user=user, token=token)
        flash('已向您的邮箱{email}发送一封确认账号邮件'.format(email=user.email), 'success')
        return redirect(url_for('.register'))
    return render_template('auth/register.html', form=form)


# 确认账户路由
@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    elif current_user.confirm(token):
        db.session.commit()
        flash('感谢您的注册，已确认您的账号', 'success')
        # time.sleep(3)
        # login_user(current_user)
        return redirect(url_for('main.index'))
    else:
        flash('认证链接无效或已过期', 'danger')
        # 重定向到main蓝图是为了直接转到重发确认链接路由
        return redirect(url_for('main.index'))


# 全局使用钩子过滤未确认用户,before_app_request代表访问任何页面之前使用钩子
@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.endpoint[:5] != 'auth.' \
                and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))


# 提示用户确认链接页面路由
@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


# 重新发送确认邮件链接路由
@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    email.send_email(current_user.email, '确认您的账号', 'auth/email/confirm',
                     user=current_user, token=token)
    flash('已向您的邮箱{email}发送一封确认账号邮件'.format(email=current_user.email), 'success')
    return redirect(url_for('main.index'))


# 修改密码路由
@auth.route('/changepswd', methods=['GET', 'POST'])
@login_required
def changepswd():
    form = ChangePassword()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.new_password.data
            db.session.add(current_user)
            db.session.commit()
            flash('成功修改密码', 'success')
            return redirect(request.args.get('next') or url_for('main.index'))
        else:
            flash('原始密码错误', 'warning')
    return render_template('auth/usermanage/changepswd.html', form=form)


# 重设密码路由（前）
@auth.route('/resetpswd', methods=['GET', 'POST'])
def before_resetpswd():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = BeforeResetpswd()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_resetpswd_confirmation_token()
            email.send_email(user.email, '重置您的密码', 'auth/email/resetpswd', user=user,
                             token=token)
            flash('已向您的邮箱{email}发送重置密码确认邮件'.format(email=user.email), 'success')
        else:
            flash('无此邮箱', 'danger')
        return redirect(url_for('auth.before_resetpswd'))
    return render_template('auth/usermanage/resetpswd.html', form=form)


# 重设密码路由（后）
@auth.route('/resetpswd/<token>', methods=['GET', 'POST'])
def after_resetpswd(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = AfterResetpswd()
    if form.validate_on_submit():
        if User.confirm_resetpasswd(token, form.password.data):
            db.session.commit()
            flash('已成功修改密码', 'success')
            return redirect(url_for('.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/usermanage/resetpswd.html', form=form)


# 修改用户邮箱（前）
@auth.route('/changemail', methods=['GET', 'POST'])
@login_required
def change_mail():
    form = ChangeMail()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            token = current_user.generate_changemail_confirmation_token(form.email.data)
            email.send_email(current_user.email, '重置您的邮箱', 'auth/email/changemail', user=current_user,
                             token=token)
            flash('已向您的邮箱{email}发送重置邮箱确认邮件'.format(email=current_user.email), 'success')
            return redirect(url_for('auth.change_mail'))
        else:
            flash('密码错误', 'warning')
    return render_template('auth/usermanage/changemail.html', form=form)


# 修改用户邮箱（后）
@auth.route('/changemail/<token>', methods=['GET', 'POST'])
@login_required
def change_mail_done(token):
    form = ChangeMail()
    if current_user.confirm_changemail(token):
        db.session.commit()
        flash('成功修改邮箱', 'success')
        return redirect(url_for('main.index'))
    else:
        flash('认证失败或链接已过期', 'danger')
    return render_template('auth/usermanage/changemail.html', form=form)
