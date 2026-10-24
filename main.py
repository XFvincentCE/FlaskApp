import os
from wtforms.validators import DataRequired, Length, EqualTo

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "nur-fuer-lokal-aendern")


def get_hashed_pw(plain_password):
    return hashpw(plain_password.encode("utf-8"), gensalt()).decode("utf-8")


def check_password(plain_password, hashed_password):
    return checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class RegisterForm(FlaskForm):
    username = StringField("Benutzername", validators=[DataRequired(), Length(4, 10)])
    password = PasswordField("Passwort", validators=[DataRequired(), Length(8, 30)])
    password_repeat = PasswordField(
        "Passwort wiederholen",
        validators=[DataRequired(), EqualTo("password", message="Passwörter stimmen nicht überein")],
    )
    submit = SubmitField("Registrieren")


@app.route("/")
def index():
    if current_user.is_authenticated:
        return render_template("index.html", user=current_user.username)
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password(form.password.data, user.password):
            login_user(user, remember=form.remember.data)
            flash("Du wurdest erfolgreich eingeloggt.")
            return redirect(url_for("dashboard"))
        return render_template("login.html", form=form, error="Falscher Benutzername oder Passwort")
    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            form.username.errors.append("Dieser Benutzername ist schon vergeben.")
            return render_template("register.html", form=form)
        new_user = User(username=form.username.data, password=get_hashed_pw(form.password.data))
        db.session.add(new_user)
        db.session.commit()
        flash("Registrierung erfolgreich, du kannst dich jetzt einloggen.")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user.username)


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=1414)
