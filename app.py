from flask import Flask, flash, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, current_user, LoginManager, login_user, logout_user
from dotenv import load_dotenv
import os

# Initialization

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

load_dotenv()
secret = os.getenv("secret_key")
app.config['SECRET_KEY'] = secret

db = SQLAlchemy(app)

migrate = Migrate(app, db)

bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Database

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    followers = db.Column(db.Integer, nullable=False, default=0)
    following = db.Column(db.Integer, nullable=False, default=0)
    likes = db.Column(db.Integer, nullable=False, default=0)
    pfp = db.Column(db.String(64), nullable=False, default='../static/pfp/pfp.png')


# Routes

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route("/")
def home():
    users = Users.query.all()
    return render_template("index.html", users=users)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'GET':
        return render_template("account.html")
    
    if request.method == 'POST':
        loguser = request.form.get("loguser")
        logpass = request.form.get("logpass")

        signuser = request.form.get("signuser")
        signpass = request.form.get("signpass")
        signcon = request.form.get("signcon")


        if signuser and signpass:
            if signpass == signcon:
                hashed_pw = bcrypt.generate_password_hash(signpass).decode('utf-8')
                new_user = Users(username=signuser, password=hashed_pw)
                try:
                    db.session.add(new_user)
                    db.session.commit()
                    login_user(new_user)
                    flash("Account Created Successfully", 'success')
                    return redirect(url_for("home"))
                except Exception as e:
                    db.session.rollback()
                    flash("Username Already Taken", 'fail')
                    return redirect(url_for('login'))
            else:
                flash("Passwords Do Not Match", 'fail')
                return redirect(url_for('login'))

        if loguser and logpass:
            user = Users.query.filter_by(username=loguser).first()
            if user and bcrypt.check_password_hash(user.password, logpass):
                login_user(user)
                flash("Logged In Successfully", 'success')
                return redirect(url_for('home'))
            else:
                flash("Incorrect Credentials", 'fail')
                return redirect(url_for('login'))
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/profile/<int:user_id>', methods=['GET', 'POST'])
def profile(user_id):
    user = Users.query.filter_by(id=user_id).first_or_404()
    if request.method == 'GET':
        return render_template('profile.html', user=user)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    pass

# Run

if __name__ == "__main__":
    app.run(debug=True)