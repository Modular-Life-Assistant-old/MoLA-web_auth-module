import flask_login
import hashlib
import os
from flask import request

from core import DataFileManager
from core.settings import SECRET_KEY


MODULE_NAME = __file__.split(os.sep)[-2]


def create_user(username, password):
    if not username or not password:
        return None

    user = load(username)

    if user:  # user exist
        return None

    password = hash_password(username, password)
    user = User(username, password)
    user.save()

    # add in list users
    users = DataFileManager.load(MODULE_NAME, 'users', [])
    users.append(username)
    DataFileManager.save(MODULE_NAME, 'users' , users)

    return user


def get_valid_user(username, password):
    if not username or not password:
        return None

    user = load(username)

    if not user or not user.check_password(password):
        return None

    return user


def hash_password(username, password):
    value = '%s:%s:%s' % (username, password, SECRET_KEY)
    return hashlib.sha512(value.encode()).hexdigest()


def load(username):
    user_data = DataFileManager.load(MODULE_NAME, 'user_%s' % username, {})
    return User(**user_data) if user_data else None


class User(flask_login.UserMixin):
    def __init__(self, username, password, app_allowed='*'):
        self.id = username
        self.password = password
        self.username = username
        self.app_allowed = app_allowed

    def can_access(self, app_name):
        return '*' in self.app_allowed or \
               app_name in self.app_allowed

    def check_password(self, password):
        return hash_password(self.username, password) == self.password

    @property
    def is_authenticated(self):
        return not request.blueprint or self.can_access(request.blueprint)

    def save(self):
        DataFileManager.save(MODULE_NAME, 'user_%s' % self.id, {
            'password': self.password,
            'username': self.username,
            'app_allowed': self.app_allowed,
        })

    def update_password(self, new_password):
        self.password = hash_password(self.username, new_password)
        self.save()
