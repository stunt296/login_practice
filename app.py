import csv

from flask import Flask, session, redirect, render_template, flash, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired


app = Flask(__name__)
app.secret_key = 'rain'
login_manager = LoginManager()
login_manager.init_app(app)
# without setting the login_view, attempting to access @login_required endpoints will result in an error
# this way, it will redirect to the login page
login_manager.login_view = 'login'
app.config['USE_SESSION_FOR_NEXT'] = True


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired()])
    password = PasswordField('password', validators=[InputRequired()])
    submit = SubmitField('Login')


class ForgotForm(FlaskForm):
    password = PasswordField('New password', validators=[InputRequired()])
    password2 = PasswordField('Confirm new password', validators=[InputRequired()])
    submit = SubmitField('Submit')


class User(UserMixin):
    def __init__(self, username):
        self.id = username


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


def check_password(username, password):
    with open('data/passwords.csv') as f:
        for user in csv.reader(f):
            if username == user[0] and password == user[1]:
                return True
    return False


@app.route('/')
def index():
    return render_template('Home.html')


@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('logout.html')


@app.route('/login_success')
@login_required
def loginsuccess():
    return render_template('login_success.html')


@app.route('/forgot_success')
def forgotsuccess():
    return render_template('forgot_success.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if check_password(form.username.data, form.password.data):
            login_user(User(form.username.data))
            next_page = session.get('next', '/login_success')
            session['next'] = '/login_success'
            return redirect(next_page)
        else:
            flash('Incorrect username/password!')
    return render_template('login.html', form=form)


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    form = ForgotForm()
    if form.on_submit():
        with open('data/passwords.csv') as f:
            r = csv.reader(f)
            lines = list(r)
            lines[0][1] = form.password.data
            writer = csv.writer(f)
            writer.writerows(lines)
            writer.close()
        next_page = session.get('next', '/forgot_success')
        session['next'] = '/forgot_success'
        return redirect(next_page)
    return render_template('forgot.html', form=form)


if __name__ == '__main__':
    app.run()
