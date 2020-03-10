from flask import render_template, flash, redirect, url_for, request
from datetime import datetime

from flask_wtf import Form as FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Length, ValidationError

from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hall.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return self.username

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def get_id(self):
        return self.id

class Post(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    post = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PostForm(FlaskForm):
    post = StringField('Post', validators=[DataRequired(), Length(min=2, max=200)])
    submit = SubmitField('Post')


@app.route("/")
def home():
    return render_template('home.html', current_user=current_user)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        print('Your account has been created! You are now able to login', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)



@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if (user is None):
            print('User not found')
            return render_template('login.html', title='Login', form=form)

        if (bcrypt.check_password_hash(user.password, form.password.data)):
            login_user(user, remember=True)
            print('You have been logged in!', 'success')
            return redirect(url_for('home'))
        else:
            print('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/people", methods=['GET', 'POST'])
@login_required 
def people():
    users = User.query.all()
    username = [user.username for user in users]
    return jsonify({'users': username})


@app.route("/post", methods=['GET', 'POST'])
@login_required
def post():
    form = PostForm()
    if request.method == 'POST':
        post = Post(post=form.post.data, user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        return render_template('home.html', form=form, user=user)
    return render_template('post.html', form=form)
      


if __name__ == '__main__':
    app.run(debug=True)
