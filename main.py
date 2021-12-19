import smtplib
from flask import Flask, render_template, request, flash, redirect, url_for, abort
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, URL
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
import os


app = Flask(__name__)


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
MY_EMAIL = os.environ.get('MY_EMAIL')
PASSWORD = os.environ.get('PASSWORD')


class SendForm(FlaskForm):
    name = StringField(label='Name', validators=[DataRequired()])
    email = StringField(label='Email', validators=[DataRequired()])
    message = TextAreaField(label='Message', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField(label="SEND!")

class CreatorForm(FlaskForm):
    title = StringField(label='Title', validators=[DataRequired()])
    subtitle = TextAreaField(label='Subtitle', validators=[DataRequired(), Length(min=8)])
    img_url = StringField(label='Url_img', validators=[DataRequired()])
    proj_url = StringField(label='Url_proj', validators=[DataRequired()])
    submit = SubmitField(label="Confirm")


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///work.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=False, nullable=False)
    subtitle = db.Column(db.String(2250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    proj_url = db.Column(db.String(250), nullable=False)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))


db.create_all()



def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function




@app.route('/', methods=['GET', 'POST'])
def home():
    form = SendForm()
    if request.method == 'POST':
        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(user=MY_EMAIL, password=PASSWORD)
            connection.sendmail(from_addr=MY_EMAIL,
                                to_addrs="ofaxtab@vk.com",
                                msg=f"Subject:From CV Website\n\nWho: {form.name.data}\nEmail: {form.email.data}\n\n{form.message.data}")
            flash('Success')
            return redirect('/#CONTACT_SEC')
    projects = BlogPost.query.all()
    projects = projects[0:8]
    return render_template('index.html', form=form, projects=projects)


@app.route('/works')
def works():
    projects = BlogPost.query.all()
    return render_template('works.html', projects=projects)


@app.route('/works/<int:proj_id>')
def work_view(proj_id):
    requested_project = BlogPost.query.get(proj_id)
    return render_template('work.html', proj=requested_project)


@app.route('/register', methods=['GET', 'POST'])
def register():
    class RegisterForm(FlaskForm):
        email = StringField("Email", validators=[DataRequired()])
        password = PasswordField("Password", validators=[DataRequired()])
        submit = SubmitField("Sign Me Up!")
    form = RegisterForm()
    if request.method == 'POST':
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for("admin"))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    class LoginForm(FlaskForm):
        email = StringField("Email", validators=[DataRequired()])
        password = PasswordField("Password", validators=[DataRequired()])
        submit = SubmitField("Sign Me Up!")
    form = LoginForm()
    if request.method == 'POST':
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if not user:
            return redirect(url_for('home'))
        elif not check_password_hash(user.password, password):
            return redirect(url_for('home'))
        else:
            login_user(user)
            return redirect(url_for('admin'))
    return render_template('login.html', form=form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))





@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/login/administrator')
@admin_only
def admin():
    projects = BlogPost.query.all()
    return render_template('admin.html', projects=projects)


@app.route('/login/administrator/editor/<int:proj_id>', methods=['GET', 'POST'])
@admin_only
def editor(proj_id):
    requested_project = BlogPost.query.get(proj_id)
    class EditForm(FlaskForm):
        title = StringField(label='Title', validators=[DataRequired()])
        subtitle = TextAreaField(label='Subtitle', validators=[DataRequired(), Length(min=8)], default=requested_project.subtitle)
        img_url = StringField(label='Url_img', validators=[DataRequired()])
        proj_url = StringField(label='Url_proj', validators=[DataRequired()])
        submit = SubmitField(label="Confirm")
    form = EditForm()

    if request.method == 'POST':
        requested_project.title = form.title.data
        requested_project.subtitle = form.subtitle.data
        requested_project.img_url = form.img_url.data
        requested_project.proj_url = form.proj_url.data
        db.session.commit()
        return redirect(url_for("admin"))

    return render_template('editor.html', proj=requested_project, form=form)


@app.route('/login/administrator/delete/<int:proj_id>', methods=['GET', 'POST'])
@admin_only
def delete(proj_id):
    delete_project = BlogPost.query.get(proj_id)
    db.session.delete(delete_project)
    db.session.commit()
    return redirect(url_for('admin'))


@app.route('/login/administrator/creator', methods=['GET', 'POST'])
@admin_only
def creator():
    form = CreatorForm()
    if request.method == 'POST':
        new_proj = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            img_url=form.img_url.data,
            proj_url=form.proj_url.data,
            )
        db.session.add(new_proj)
        db.session.commit()
        return redirect(url_for("admin"))
    return render_template('creator.html', form=form)




if __name__ == '__main__':
    app.run()