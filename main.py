from flask_bootstrap import Bootstrap5
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, UserMixin, login_user, logout_user, current_user
from bcrypt import hashpw, checkpw, gensalt

db = SQLAlchemy()
app = Flask(__name__, template_folder="templates")
bootstrap = Bootstrap5(app)
app.config['SECRET_KEY'] = "myKey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

def get_hashed_pw(plain_password):
    return hashpw(plain_password.encode('utf-8'), gensalt())

def check_password(plain_password, hashed_password):
    return checkpw(plain_password.encode('utf-8'), hashed_password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

class RegisterForm(FlaskForm):
    username = StringField("username", validators=[DataRequired(), Length(4, 10)])
    password = PasswordField("password", validators=[DataRequired(), Length(8, 30)])
    password_repeat = PasswordField("wiederhole dein passsword", validators=[DataRequired(), Length(8, 30)])
    submit = SubmitField()

class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired(), Length(4, 10)])
    password = PasswordField("password", validators=[DataRequired(), Length(8, 30)])
    remember = BooleanField("remember me?")
    submit = SubmitField()

with app.app_context():
    db.create_all()
@app.route('/')
def index():
    if current_user.is_active:
        return render_template("index.html", user=current_user.username)
    return render_template('index.html')
@app.route("/Login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        print(user.password)
        if user and check_password(form.password.data, user.password):
            login_user(user, remember=form.remember.data)
            flash("du wurdest erfolgreich eingeloggt ")
            return redirect(url_for("dashboard"))
        return render_template("login.html", form=form, error="Wrong Username or Password")
    return render_template("login.html", form=form)
@app.route("/Register",  methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = get_hashed_pw(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return  redirect(url_for("index"))
    return render_template('register.html', form=form)
@app.route("/Dashboard")
def dashboard():
    return render_template("dashboard.html", user=current_user.username)

@app.route("/Logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(debug=True, port=1414)

"hallo wie gehts"
