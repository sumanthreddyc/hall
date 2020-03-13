#import os
#import secrets
from flask import render_template, flash, redirect, url_for, request
from datetime import datetime

from flask_wtf import Form as FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Length, ValidationError
from flask_wtf.file import FileField, FileAllowed

from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from PIL import Image


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
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')

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
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')


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

class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png', 'pdf'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')


@app.route("/")
def home():
    posts = Post.query.all()
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.username.data = current_user.username
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('home.html', current_user=current_user, posts=posts, image_file=image_file, form=form)


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
    print('working')
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
    return redirect(url_for('first'))



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

@app.route("/home")
def first():
    posts = Post.query.all()
    return render_template('first.html', posts=posts)

#(form_picture):
    #random_hex = secrets.token_hex(8)
    #_, f_ext = os.path.splitext(form_picture.filename)
    #picture_fn = random_hex + f_ext
    #picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    #output_size = (125, 125)
    #i = Image.open(form_picture)
    #i.thumbnail(output_size)
    #i.save(picture_path)

    #return picture_fn

#@app.route("/account", methods=['GET', 'POST'])
#@login_required
#def account():
    #form = UpdateAccountForm()
    #if form.validate_on_submit():
        #if form.picture.data:
            #picture_file = save_picture(form.picture.data)
            #current_user.image_file = picture_file
        #current_user.username = form.username.data
        #db.session.commit()
        #flash('Your account has been updated!', 'success')
        #return redirect(url_for('account'))
    #elif request.method == 'GET':
        #form.username.data = current_user.username
    #image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    #return render_template('account.html', title='Account',
                           #image_file=image_file, form=form)
      

if __name__ == '__main__':
    app.run(debug=True)
