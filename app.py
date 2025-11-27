from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, current_user, LoginManager, login_required, login_user, logout_user
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
    liked_posts = db.Column(db.String, default="")

class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(64), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(64), nullable=True)
    likes = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=db.func.now())

    user = db.relationship('Users', backref=db.backref('posts', lazy=True))

class List(db.Model):

    # To Do:
    # Private/Public Lists (User Gets To Choose If It's Public Or Private While Making Them )
    # Save Lists to go back to them in the future

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(64), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    private = db.Column(db.Boolean, nullable=False)
    user = db.relationship('Users', backref='lists')

# Routes

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route("/", methods=['GET', 'POST'])
def home():
    users = Users.query.all()
    posts = Posts.query.all()
    if request.method == 'GET':
        return render_template("index.html", users=users, posts=posts)
    if request.method == 'POST':
        title = request.form.get('postTitle')
        desc = request.form.get('postDesc')
        image = request.files.get('img')

        filename = None
        if image and image.filename:
            filename = image.filename
            path = f'static/posts/{filename}'
            image.save(path)

        new_post = Posts(user_id=current_user.id, title=title, content=desc, image=filename)
        db.session.add(new_post)
        db.session.commit()
        flash("Successfully Created Post", 'success')
        return redirect(url_for('home'))

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
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/profile/<int:user_id>', methods=['GET', 'POST'])
@login_required
def profile(user_id):
    user = Users.query.filter_by(id=user_id).first_or_404()
    if request.method == 'GET':
        return render_template('profile.html', user=user)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'GET':
        return render_template('settings.html')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        image = request.files.get('pfp')

        current_pass = request.form.get('currentpass')

        new_pass = request.form.get('newpass')

        if username and password:
            if bcrypt.check_password_hash(current_user.password, password):
                current_user.username = username
                db.session.commit()
                flash("Username Updated Successfully", 'success')
                return redirect(url_for('settings'))
            else:
                flash("Incorrect Password", 'fail')
                return redirect(url_for('settings'))
    
        if image:
            filename = image.filename
            path = f'static/pfp/{filename}'
            image.save(path)

            current_user.pfp = f'../static/pfp/{filename}'
            db.session.commit()

            flash('Profile Updated', 'success')
            return redirect(url_for('settings'))


        if current_pass and new_pass:
            if bcrypt.check_password_hash(current_user.password, current_pass):
                new_hash = bcrypt.generate_password_hash(new_pass).decode('utf-8')
                current_user.password = new_hash
                db.session.commit()
                flash("Password Changed Successfully", 'success')
                return redirect(url_for('settings'))
            else:
                flash("Incorrect Password", 'fail')
                return redirect(url_for('settings'))
        
@app.route('/delete')
@login_required
def delete():
    user = Users.query.filter_by(id=current_user.id).first()
    db.session.delete(user)
    db.session.commit()
    flash("Account Deleted Successfully", 'fail')
    return redirect(url_for('home'))


@app.route('/delete/post/<int:post_id>')
@login_required
def delete_post(post_id):
    post = Posts.query.filter_by(id=post_id).first()
    db.session.delete(post)
    db.session.commit()
    flash("post deleted")
    return redirect(url_for('home'))


@app.route('/list', methods=['GET', 'POST'])
@login_required
def list():
    lists = List.query.filter_by(private=False).all()
    your = List.query.filter_by(user_id=current_user.id).all()
    if request.method == 'GET':
        return render_template('list.html', lists=lists, your=your)


@app.route('/list/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form.get('title')
        public = request.form.get('public')
        private = request.form.get('private')

        if public == 'yes':
            new_list = List(title=title, user_id=current_user.id, private=False)
        elif private == 'yes':
            new_list = List(title=title, user_id=current_user.id, private=True)
        
        db.session.add(new_list)
        db.session.commit()
        return redirect(url_for('list'))


# Run

if __name__ == "__main__":
    app.run(debug=True) 