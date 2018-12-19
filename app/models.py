#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, AnonymousUserMixin
from . import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request
from datetime import datetime
import hashlib


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')
    # backref向User模型中添加一个role属性,这一属性可替代role_id访问Role模型，此时获取的是模型对象，而不是外键的值

    @staticmethod
    def insert_roles():
        """这个方法可以将角色添加到数据库，替代手动添加"""
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class Permission:
    FOLLOW = 0x01   # 关注用户
    COMMENT = 0x02  # 在他人文章发表评论
    WRITE_ARTICLES = 0x04   # 写文章
    MODERATE_COMMENTS = 0x00    # 管理他人发表的评论
    ADMINISTER = 0x80   # 管理员权限


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))     # 真实姓名
    location = db.Column(db.String(64))     # 所在地
    about_me = db.Column(db.TEXT())     # 自我介绍
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)    # 注册日期，default参数可以接收函数为默认值
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)       # 最后访问日期
    avatar_hash = db.Column(db.String(32), unique=True, index=True)         # 储存头像MD5哈希值
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        """Python与其他语言不同，子类的初始化不会自动地调用父类的初始化。
        使用内置的super可以根据MRO实现父类的代理，在这里就是调用了父类的
        __init__进行初始化。如果不显式地调用该方法，则父类的属性在子类的
        实例中就会缺失。"""
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = self.gravatar_hash()

    def can(self, permissions):
        return self.role is not None and (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

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
        return s.dumps({'confirm': self.id, 'new_email': new_email}).decode('utf-8')

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
        self.avatar_hash = hashlib.md5(self.email.encode('utf-8')).hexdigest() or self.gravatar_hash()
        db.session.add(self)
        return True

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def __repr__(self):
        return '<User %r>' % self.username  # print类实例将打印用户名

    # 生成用户头像使用的邮件地址MD5
    def gravatar_hash(self):
        return hashlib.md5(self.email.encode('utf-8')).hexdigest()

    # 用户头像方法，使用gravatar.com头像服务
    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or self.gravatar_hash()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(url=url, hash=hash, size=size,
                                                                     default=default, rating=rating)

    # 生成虚拟用户
    @staticmethod
    def generate_fake(count=100):
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u = User(email=forgery_py.internet.email_address(),
                     username=forgery_py.internet.user_name(True),
                     password=forgery_py.lorem_ipsum.word(),
                     confirmed=True,
                     name=forgery_py.name.full_name(),
                     location=forgery_py.address.city(),
                     about_me=forgery_py.lorem_ipsum.sentence(),
                     member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # 生成虚拟文章
    @staticmethod
    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()
        for i in range(count):
            # offset是跳过几次查询
            u = User.query.offset(randint(0, user_count - 1)).first()
            p = Post(body=forgery_py.lorem_ipsum.sentences(randint(1, 3)),
                     timestamp=forgery_py.date.date(True),
                     author=u)
            db.session.add(p)
            db.session.commit()


# flask_login要求实现一个回调函数，接收Unicode字符串标书的用户标识符，
# 如果能找到用户，返回用户对象，否则返回None
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
