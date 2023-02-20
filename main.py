from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditor, CKEditorField
import requests
import smtplib
import os
from datetime import datetime
from functools import wraps
from flask import abort

# -------------------------------------------------------------------------- #
# ------------------------------- SMTP LIBRARY  ---------------------------- #
# --------------------------- ----------------------------------------------- #
OWN_EMAIL = os.environ.get('BLOG-APP-EMAIL')
OWN_PASSWORD = os.environ.get('BLOG-APP-PASSWORD')


def send_email(name, email, phone, message):
    """
    function that activates the SMTP LIBRARY to send the email message

    :param name: name of the receiver
    :param email: email of the receiver
    :param phone: phone number of the receiver
    :param message: message to be sent to the receiver

    :return: None
    """
    email_message = f"Subject:New Message\n\n" \
                    f"Name: {name}\n" \
                    f"Email: {email}\n" \
                    f"Phone: {phone}\n" \
                    f"Message:{message}"

    with smtplib.SMTP("smtp.gmail.com", 421) as connection:
        connection.starttls()
        connection.login(OWN_EMAIL, OWN_PASSWORD)
        connection.sendmail(OWN_EMAIL, OWN_EMAIL, email_message)


# -------------------------------------------------------------------------- #
# ------------------------------- FLASK APPLICATION ------------------------ #
# -------------------------------------------------------------------------- #
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'

ckeditor = CKEditor(app)
Bootstrap(app)

# -------------------------------------------------------------------------- #
# ------------------------------- SETUP DATABASE --------------------------- #
# -------------------------------------------------------------------------- #
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CONNECT FLASK APP TO THE BLOGS DATABASE
db = SQLAlchemy(app)

# initialize flask login
login_manager = LoginManager()
login_manager.init_app(app)

# SOURCE OF BLOG POST
# post_url = 'https://api.npoint.io/5f37ba3bc35076eafb69'
# all_post = requests.get(post_url).json()


with app.app_context():
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    # Create admin-only decorator
    def admin_only(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # If id is not 1 then return abort with 403 error
            if current_user.id != 1:
                return abort(403)
            # Otherwise continue with the route function
            return f(*args, **kwargs)

        return decorated_function


    # CONFIGURE TABLE
    class BlogPost(UserMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        title = db.Column(db.String(250), unique=True, nullable=False)
        subtitle = db.Column(db.String(250), nullable=False)
        date = db.Column(db.String(250), nullable=False)
        body = db.Column(db.Text, nullable=False)
        author = db.Column(db.String(250), nullable=False)
        img_url = db.Column(db.String(250), nullable=False)


    class User(UserMixin, db.Model):
        __tablename__ = "users"
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(100), unique=True)
        password = db.Column(db.String(100))
        name = db.Column(db.String(100))


    # db.create_all()


    class RegisterForm(FlaskForm):
        email = StringField("Email", validators=[DataRequired()])
        password = PasswordField("Password", validators=[DataRequired()])
        name = StringField("Name", validators=[DataRequired()])
        submit = SubmitField("Sign Me Up!")


    class LoginForm(FlaskForm):
        email = StringField("Email", validators=[DataRequired()])
        password = PasswordField("Password", validators=[DataRequired()])
        submit = SubmitField("Let Me In!")


    class CreatePostForm(FlaskForm):
        title = StringField("Blog Post Title", validators=[DataRequired()])
        subtitle = StringField("Subtitle", validators=[DataRequired()])
        author = StringField("Your Name", validators=[DataRequired()])
        img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
        body = CKEditorField("Blog Content", validators=[DataRequired()])
        submit = SubmitField("Submit Post")


    @app.route('/', methods=['GET'])
    def home_page():
        if current_user.is_authenticated:
            all_post = BlogPost.query.all()
            return render_template('index.html', posts=all_post, logged_in=current_user.is_authenticated, id=current_user.id)
        else:
            return render_template('authenticate-user.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegisterForm()
        if form.validate_on_submit():
            # check if user has registered
            if User.query.filter_by(email=request.form.get('email')).first():
                flash("You've already signed up with that email, log in instead!")
                return redirect(url_for('login'))

            hash_salt_password = generate_password_hash(
                password=request.form.get('password'),
                method='pbkdf2:sha256',
                salt_length=8
            )

            new_user = User(
                email=request.form.get('email'),
                password=hash_salt_password,
                name=request.form.get('name'),
            )

            db.session.add(new_user)
            db.session.commit()

            # login and authenticate users after they have logged in into the database
            login_user(new_user)
            return redirect(url_for("home_page"))

        return render_template("register.html", form=form)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            # obtain the user's email and password entries
            email = request.form.get('email')
            password = request.form.get('password')

            # check if stored password hash corresponds to the entered password hash
            user = User.query.filter_by(email=email).first()

             # email doesn't exist
            if not user:
                flash("That email does not exist, please try again.")
                return redirect(url_for('login'))
            # password incorrect
            elif not check_password_hash(user.password, password):
                flash('Password incorrect, please try again.')
                return redirect(url_for('login'))
            # Email exists and password correct
            else:
                login_user(user)
                return redirect(url_for('home_page'))

        return render_template("login.html", form=form)

    @app.route('/logout')
    def logout():
        logout_user()
        return redirect(url_for('home_page'))

    @app.route("/post/<int:post_id>")
    def show_post(post_id):
        requested_post = BlogPost.query.get(post_id)
        return render_template("show_post.html", post=requested_post, post_id=post_id, current_user_id=current_user.id)

    @app.route('/new-post', methods=['GET', 'POST'])
    @admin_only
    def new_post():
        form = CreatePostForm()
        if form.validate_on_submit():
            newer_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                date=datetime.now().strftime('%B %d, %Y'),
                body=form.body.data,
                author=form.author.data,
                img_url=form.img_url.data
            )
            db.session.add(newer_post)
            db.session.commit()
            return redirect(url_for('home_page'))
        return render_template('make-post.html', form=form)

    @app.route('/edit-post/<int:post_id>', methods=['GET', 'POST'])
    @admin_only
    def edit_post(post_id):
        post_to_edit = BlogPost.query.get(post_id)
        edit_form = CreatePostForm(
            title=post_to_edit.title,
            subtitle=post_to_edit.subtitle,
            img_url=post_to_edit.img_url,
            author=post_to_edit.author,
            body=post_to_edit.body
        )
        if edit_form.validate_on_submit():
            post_to_edit.title = edit_form.title.data
            post_to_edit.subtitle = edit_form.subtitle.data
            post_to_edit.img_url = edit_form.img_url.data
            post_to_edit.title = edit_form.title.data
            post_to_edit.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        return render_template('edit_post.html', form=edit_form, is_edit=True)


    @app.route("/delete/<int:post_id>")
    @admin_only
    def delete_post(post_id):
        selected_post = BlogPost.query.get(post_id)
        db.session.delete(selected_post)
        db.session.commit()
        return redirect(url_for('home_page'))

    @app.route('/about')
    def about():
        return render_template('about.html', logged_in=current_user.is_authenticated)


    @app.route('/contact', methods=['POST', 'GET'])
    def contact():
        if request.method == 'POST':
            data = request.form
            send_email(data['name'], data['email'], data['phone'], data['text'])

            return render_template('contact.html', meth=request.method, msg_sent=False, logged_in=current_user.is_authenticated)
        return render_template('contact.html', msg_sent=False, logged_in=current_user.is_authenticated)


    # ------------------------------------------------------------------------ #
    # ----------------------------- RUNNING THE APP -------------------------- #
    # ------------------------------------------------------------------------ #
    if __name__ == '__main__':
        app.run(debug=True)
