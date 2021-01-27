import sqlite3

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

SALT_LENGTH = 8
HASH_METHOD = "pbkdf2:sha256"

app = Flask(__name__, static_folder="static")

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


def hash_password(password_text):
    """converts password into hashed value"""
    return generate_password_hash(password_text, method=HASH_METHOD, salt_length=SALT_LENGTH)

def login_exists(email_text):
    """determines whether specified email already has an account"""
    return User.query.filter_by(email=email_text).first() is not None


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not login_exists(request.form.get("email")):
            # Initialise user object
            user_details = User(
                email=request.form.get("email"),
                password=hash_password(request.form.get("password")),
                name=request.form.get("name")
            )
            #Log insert transaction
            db.session.add(user_details)
            #Commit transaction
            db.session.commit()
            login_user(user_details)
            return redirect(url_for("secrets", name=request.form.get("name")))
        else:
            flash("User details already registered. Proceed to use Login method.")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Initialise user object
        user_details = User.query.filter_by(email=request.form.get("email")).first()
        if user_details is not None:
            if check_password_hash(user_details.password, request.form.get("password")):
                # Valid Details
                login_user(user_details)
                return redirect(url_for("secrets", name=user_details.name))
            else:
                flash("User details not recognised. Incorrect Password.")
        else:
            flash("User details not recognised. Unknown email. Try registering first.")
    return render_template("login.html",logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=request.args.get("name"), logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/download')
@login_required
def download():
    return send_from_directory(
        app.static_folder+"/files", "cheat_sheet.pdf", as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)
