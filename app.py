import csv
import bcrypt

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


class User(UserMixin):
    def __init__(self, username, password=None):
        self.id = username
        self.password = password


# this is used by flask_login to get a user object for the current user
@login_manager.user_loader
def load_user(user_id):
    user = find_user(user_id)
    # user could be None
    if user:
        # if not None, hide the password by setting it to None
        user.password = None
    return user


def find_user(username):
    with open('data/users.csv') as f:
        for user in csv.reader(f):
            if username == user[0]:
                return User(*user)
    return None


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired()])
    password = PasswordField('password', validators=[InputRequired()])
    submit = SubmitField('login')


class ForgotForm(FlaskForm):
    password = PasswordField('New password', validators=[InputRequired()])
    password2 = PasswordField('Confirm new password', validators=[InputRequired()])
    submit = SubmitField('Submit')


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
        user = find_user(form.username.data)
        if form.username.data == 'admin' and user.password == form.password.data:
            login_user(user)
            next_page = session.get('next', '/login_success')
            session['next'] = '/login_success'
            return redirect(next_page)
        else:
            flash('Incorrect username or password!')
    return render_template('login.html', form=form)


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    form = ForgotForm()
    if form.validate_on_submit():

        with open('data/users.csv') as inf:
            reader = csv.reader(inf.readlines())

        with open('data/users.csv', 'w') as f:
            writer = csv.writer(f)
            for line in reader:
                if line[0] == 'admin':
                    writer.writerow([line[0], form.password.data])
                    break
                else:
                    writer.writerow(line)
            writer.writerows(reader)
        return redirect('/forgot_success')
    return render_template('forgot.html', form=form)


if __name__ == '__main__':
    app.run()
