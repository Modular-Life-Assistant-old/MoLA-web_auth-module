import os
from flask import flash, Blueprint, redirect, request, render_template, \
    session, url_for
from flask.ext.login import LoginManager, login_required, login_user,\
    logout_user

from core import DataFileManager, ModuleManager
from helpers.modules.BaseModule import BaseModule
from . import auth


class Module(BaseModule):
    def started(self):
        """Register mapping url to web server"""
        template_folder = os.path.join(self.module_path, 'templates')
        app = Blueprint('Auth', __name__, url_prefix='/auth',
                        template_folder=template_folder)

        # url mapping
        app.add_url_rule('/', 'index', view_func=self._index)
        app.add_url_rule('/login', 'login', view_func=self._login,
                         methods=['GET', 'POST'])
        app.add_url_rule('/logout', 'logout', view_func=self._logout)
        app.add_url_rule('/users', 'users', view_func=self._users)
        app.add_url_rule('/user', 'new_user', view_func=self._user,
                         methods=['GET', 'POST'])
        app.add_url_rule('/user/<user_name>', 'user', view_func=self._user,
                         methods=['GET', 'POST'])

        # register to flask
        module = ModuleManager.get('web')
        if not module:
            self.add_critical('no module name "web"')
            raise FileNotFoundError

        module.add_blueprint(app)
        login_manager = LoginManager()
        login_manager.login_view = '%s.login' % app.name
        login_manager.init_app(module.flask)
        login_manager.user_loader(auth.load)

        # set url to login required
        exclude_login_required_url = [
            'static',
            login_manager.login_view
        ] + DataFileManager.load(self.name, 'exclude_login_required_url', [])

        for endpoint, view_func in module.flask.view_functions.copy().items():
            if endpoint not in exclude_login_required_url:
                module.flask.view_functions[endpoint] = login_required(view_func)

    def _index(self):
        """Index page"""
        return redirect(url_for('.users'))

    def _login(self):
        """Login page"""
        error = ''

        if request.method == 'POST':
            username = request.form.get('user')
            password = request.form.get('password')
            user = auth.get_valid_user(username, password)

            if user:
                self.fire('login', type='web', user=user)
                session.permanent = not request.form.get('remember')
                if login_user(user, remember=session.permanent):
                    flash('Logged in successfully!', 'success')
                    return redirect(request.args.get('next') or url_for('index'))

                else:
                    error = 'This username is disabled!'
            else:
                error = 'Wrong username or password!'

        return render_template('login.html', error=error)

    def _logout(self):
        logout_user()
        flash('You have logged out!')
        return redirect(url_for('.login'))

    def _user(self, user_name=''):
        user = auth.load(user_name)
        error = ''

        if not user and user_name:
            return redirect(url_for('.users'))

        if request.method == 'POST':
            password = request.form.get('password')
            password_check = request.form.get('password_check')

            if password:
                if password == password_check:
                    if user:  # update
                        user.update_password(password)
                        self.fire('update_user', type='web', user=user)
                    else:
                        username = request.form.get('user')
                        user = auth.create_user(username, password)
                        self.fire('create_user', type='web', user=user)
                        return redirect(url_for('.users'))

                else:
                    error = 'Password not match'

        return render_template('user.html', user=user, error=error)



    def _users(self):
        users = DataFileManager.load(self.name, 'users', []).sort()
        return render_template('users.html', users=users)