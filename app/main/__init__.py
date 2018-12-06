#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Blueprint

main = Blueprint('main', __name__)


@main.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)


from . import views, errors
