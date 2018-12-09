#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from functools import wraps
from flask import abort
from flask_login import current_user
from .models import Permission

"""这是自定义装饰器，用来检查用户权限"""


def permission_required(permisssion):
    def decorator(f):
        @wraps(f)
        # @wraps(f)的用处，是使执行的函数名等于原始函数，即func.__name__输出'func'
        def decorated_function(*args, **kwargs):
            if not current_user.can(permisssion):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    return permission_required(Permission.ADMINISTER)(f)
