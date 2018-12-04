#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from ..models import User
from wtforms import ValidationError


class LoginForm(FlaskForm):
    email = StringField('邮件', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('密码', validators=[DataRequired(), Length(3, 16)])
    remember_me = BooleanField('记住我')
    submit = SubmitField('登陆')


class RegistrationForm(FlaskForm):
    email = StringField('邮件', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('用户名', validators=[DataRequired(), Length(1, 64),
                                              Regexp('^[A-Za-z][A-Za-z0-9_]*$', 0,
                                                     '用户名只能是字母、数字或下划线')])
    password = PasswordField('密码', validators=[DataRequired(), Length(3,16),
                                               EqualTo('password2', message='两次输入密码必须一致')])
    password2 = PasswordField('确认密码', validators=[DataRequired()])
    submit = SubmitField('注册')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('该邮箱已注册')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('该用户名已注册')


class ChangePassword(FlaskForm):
    old_password = PasswordField('请输入旧密码', validators=[DataRequired(), Length(3,16)])
    new_password = PasswordField('请输入新密码', validators=[DataRequired(), Length(3,16),
                                                     EqualTo('new_password2', message='两次输入密码不一致')])
    new_password2 = PasswordField('请确认新密码', validators=[DataRequired()])
    submit = SubmitField('提交修改')


class BeforeResetpswd(FlaskForm):
    email = StringField('请输入邮箱', validators=[DataRequired(), Length(1, 64), Email()])
    submit = SubmitField('发送邮件')


class AfterResetpswd(FlaskForm):
    password = PasswordField('请输入新密码', validators=[DataRequired(), Length(3, 16),
                                                   EqualTo('password2', message='两次输入密码不一致')])
    password2 = PasswordField('请确认新密码', validators=[DataRequired()])
    submit = SubmitField('确认重置')


class ChangeMail(FlaskForm):
    email = StringField('请输入新邮箱', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('请输入密码', validators=[DataRequired(), Length(3, 16)])
    submit = SubmitField('提交修改')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('该邮箱已注册，换一个试试')
