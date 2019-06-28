from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField, ValidationError, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, LoginManager,\
                        UserMixin, current_user
import os
app = Flask (__name__)

POSTGRES = {
    'user': os.environ['POSTGRES_USER'],
    'pw': os.environ['POSTGRES_PWD'],
    'db': os.environ['POSTGRES_DB'],
    'host': os.environ['POSTGRES_HOST'],
    'port': os.environ['POSTGRES_PORT'],
}

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:\
%(port)s/%(db)s' % POSTGRES

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SECRET_KEY'] = "very secret"

db = SQLAlchemy(app)
migrate = Migrate(app, db)
#Create connection between app and login:
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(80), nullable = False, unique = True)
    email = db.Column(db.String(255), nullable = False, unique = True)
    password = db.Column(db.String(255), nullable = False)

    def __repr__(self):
        return "<User {}>".format(self.username)
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)

db.create_all()

class Post(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(500), nullable = False)
    body = db.Column(db.String(999), nullable = False)
    author_name = db.Column(db.String(255), nullable = False)
    created_on = db.Column(db.DateTime, server_default = db.func.now())
    updated_on = db.Column(db.DateTime, server_default = db.func.now(), server_onupdate = db.func.now())

db.create_all()

# Defind form here:

class RegistrationForms(FlaskForm):
    username = StringField("UserName", validators = [DataRequired(), Length(max=80)])
    email = StringField("Email", validators = [DataRequired(), Length(max=254)])
    password = PasswordField("Password", validators=[DataRequired(),
                                                    EqualTo('password_confirm')])
    password_confirm = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    #using this function to check username:
    def check_username(self, field):
        if User.query.filter_by(username = field.data).first():
            raise ValidationError("Your username has been registered")

    def validate_email(self, field):
        if User.query.filter_by(email = field.data).first():
            raise ValidationError("Your email has been registered!")

class create_post(FlaskForm):
    title = StringField("Title", validators = [DataRequired(), Length(max = 255, min = 10)])
    body = TextAreaField("Body", validators = [DataRequired(), Length(min = 20)])
    submit = SubmitField('Post')


class LoginForm(FlaskForm):
    username = StringField("User Name", validators = [DataRequired()])
    password = PasswordField("Password", validators = [DataRequired()])
    submit = SubmitField('Login')


@app.route('/')
def index():
    my_text = "Welcome to Pepe the Blog"
    return render_template("index.html", text_here = my_text)

# @app.route('/<username>/<email>')
# def create_user(username, email):
#     new_user = User(username = username, email = email)
#     db.session.add(new_user)
#     db.session.commit()
#     return "Create new User: " + username

@app.route('/register', methods = ['get', 'post'])
def register_user():
    form = RegistrationForms()
    if form.validate_on_submit():
        new_user = User(username = form.username.data,
                        email = form.email.data)
        new_user.set_password(form.password.data)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login")) #looking for url
    return render_template('register.html', form = form)


@app.route('/thanks')
def thanks():
    return "Thanks for register!!!"

@app.route('/login', methods = ['get','post'])
def login ():
    form = LoginForm()
    if form.validate_on_submit():
        log_user = User.query.filter_by(username = form.username.data).first()
        if log_user is None:
            flash("Your account dosen't exist")
            return redirect(url_for('login'))
        # make sure user exsist

        if not log_user.check_password(form.password.data):
            return render_template('login.html', form = form)

        login_user(log_user)
        return redirect(url_for('all_post'))

    return render_template('login.html', form = form)


@app.route('/all_post')
def all_post():
    all_post = Post.query.all()
    return render_template('all_post.html', all_post = all_post)


@app.route('/logout')
def logout():
    logout_user()
    flash("Logout success")
    return redirect(url_for('all_post'))



@app.route('/create_post', methods = ['get', 'post'])
def create_new_post():
    post = create_post()
    if current_user.is_anonymous:
        flash("You Have to Login First")
        return redirect(url_for('login'))
    if post.validate_on_submit():
        new_post = Post(title = post.title.data, 
                        author_name = current_user.username,
                        body = post.body.data)
        db.session.add(new_post)
        db.session.commit()
        flash('Post created')
        return redirect(url_for('all_post'))
    
    return render_template('create_post.html', post = post)

@app.route('/all_post/<int:post_id>', methods = ['get', 'post'])
def edit_post(post_id):
    OGpost = Post.query.get(post_id)
    post_update = create_post()
    if current_user.is_anonymous:
        flash("You Have to Login First")
        return redirect(url_for('login'))
    if OGpost.author_name != current_user.username:
        flash("You can not edit this post")
        return redirect(url_for('all_post'))
    if post_update.validate_on_submit() and OGpost.author_name == current_user.username:
        OGpost.title = post_update.title.data
        OGpost.body = post_update.body.data
        db.session.commit()
        return redirect(url_for('all_post'))

    return render_template('editPost.html', post = post_update, OGpost = OGpost)

if __name__ == '__main__':
    app.run(debug = True)