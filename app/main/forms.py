#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, Email, Regexp, ValidationError
from ..models import Role, User


class NameForm(FlaskForm):
    name = StringField('你的名字？', validators=[DataRequired()])
    name_v = StringField('请再次输入', validators=[DataRequired()])
    submit = SubmitField('提交')


class EditProfileForm(FlaskForm):
    name = StringField('真实姓名', validators=[Length(0, 64)])
    location = StringField('所在地', validators=[Length(0, 64)])
    about_me = TextAreaField('简介')
    submit = SubmitField('修改')


class EditProfileAdminForm(FlaskForm):
    email = StringField('邮件', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('用户名', validators=[DataRequired(), Length(1, 64),
                                              Regexp('^[A-Za-z][A-Za-z0-9_]*$', 0,
                                                     '用户名只能是字母、数字或下划线')])
    confirmed = BooleanField('验证状态')
    role = SelectField('角色', coerce=int)
    name = StringField('真实姓名', validators=[Length(0, 64)])
    location = StringField('所在地', validators=[Length(0, 64)])
    about_me = TextAreaField('简介')
    submit = SubmitField('修改')

    def __init__(self, user, *args, **kwargs):
        super.__init__(*args, **kwargs)
        # order_by为按字母顺序排序查询
        self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and User.query.filter_by(email=field.data).first():
            raise ValidationError('邮件地址已被注册')

    def validate_username(self, field):
        if field.data != self.user.username and User.query.filter_by(username=field.data).first():
            raise ValidationError('用户名已被注册')
