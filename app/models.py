#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from . import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role')  # backref向User模型中添加一个role属性

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)

    @property
    def password(self):
        raise AttributeError(u'密码不是可读的属性')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id}).decode('utf-8')

    def generate_resetpswd_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'] + 'resetpassword', expiration)
        return s.dumps({'reset': self.id}).decode('utf-8')

    def generate_changemail_confirmation_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'] + 'changemail', expiration)
        return s.dumps({'confirm': self.id, 'email': new_email}).decode('utf-8')

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    @staticmethod
    def confirm_resetpasswd(token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'] + 'resetpassword')
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        user = User.query.get(data.get('reset'))
        if user is None:
            return False
        user.password = new_password
        db.session.add(user)
        return True

    def confirm_changemail(self, token):
        s = Serializer(current_app.config['SECRET_KEY'] + 'changemail')
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if self.id != data.get('confirm'):
            return False
        if data.get('new_email') is None:
            return False
        if User.query.filter_by(email=data.get('new_email')).first() is not None:
            return False
        self.email = data.get('new_email')
        db.session.add(self)
        return True

    def __repr__(self):
        return '<User %r>' % self.username  # print类实例将打印用户名


# flask_login要求实现一个回调函数，接收Unicode字符串标书的用户标识符，
# 如果能找到用户，返回用户对象，否则返回None
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
