from flask import Flask, jsonify, redirect, render_template, url_for, request
from flask_wtf import FlaskForm
from flask_cors import CORS
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from models import db, User, Book
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)
import requests

app = Flask(__name__)
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "sqlite:///site.db"
app.config["SECRET_KEY"] = "secretkey"

db.init_app(app)

CORS(app)

with app.app_context():
    db.create_all()
    print("created")


bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        user = User(
            username=form.username.data, email=form.email.data, password=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("signin"))

    return render_template("signup.html", form=form)


@app.route("/", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            print("Login successful!", "success")
            return redirect(url_for("profile"))
        else:
            print("Login unsuccessful. Please check your email and password.", "danger")

    return render_template("signin.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


@app.route("/recommendations", methods=["POST"])
def get_recommendations():
    try:
        pref = request.get_json()
        genre = pref.get("genre")
        book_length = pref.get("bookLength")
        tone_mood = pref.get("toneMood")
        setting = pref.get("setting")
        time_period = pref.get("timePeriod")
        print(request)
        preferences = {
            "genre": genre,
            "bookLength": book_length,
            "toneMood": tone_mood,
            "setting": setting,
            "timePeriod": time_period,
        }
        all_books = Book.query.all()
        prompt = f"Recommend books with the following preferences:\nGenre: {preferences['genre']}\nBook Length: {preferences['bookLength']}\nTone/Mood: {preferences['toneMood']}\nSetting: {preferences['setting']}\nTime Period: {preferences['timePeriod']} return only the book title and 5 movies in all from the given movies {all_books} make sure that the movie exists in this list."
        print(prompt)
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            json={
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7,
            },
            headers={"Authorization": "Bearer sk-....."},
        )
        recommendations = response.json()
        result = recommendations["choices"][0]["message"]["content"]
        return jsonify({"recommendations": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True)
