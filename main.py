from flask import  Flask, render_template, redirect, url_for, flash, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort


app = Flask(__name__)
app.config['SECRET_KEY'] = 'os.environ.get("SECRET_KEY")'

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url="None")

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo_tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


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


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)

    # This will act like a List of tasks objects attached to each User.
    # The "username" refers to the username property in the Tasks class.
    task_list = relationship("Tasks", back_populates="username")


class Tasks(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    # Create reference to the User object, the "tasks" refers to the tasks property in the User class.
    username = relationship("User", back_populates="task_list")

    task_name = db.Column(db.String(250), nullable=False)
    task_date = db.Column(db.String(250), nullable=False)
    task_time = db.Column(db.String(250), nullable=False)
    task_priority = db.Column(db.String(250), nullable=False)
    task_status = db.Column(db.String(250), nullable=False)


@app.route('/', methods=['GET', 'POST'])
def logon():
    if request.method == 'POST':
        form_email = request.form['email']
        form_password = request.form['password']

        user = db.session.query(User).filter_by(email=form_email).first()

        if not user:
            flash('That email does not exist, please try again', 'error')
        else:
            if not check_password_hash(user.password, form_password):
                flash('Password incorrect, please try again', 'error')
            else:
                login_user(user)
                task_list = db.session.query(Tasks).filter_by(user_id=user.id)

                return render_template("home.html", current_user=current_user, users=user, task_list=task_list)

    return render_template("login.html", current_user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':
        # Get the Entered details from Form - HTML
        form_name = request.form['username']
        form_password = request.form['password']
        form_email = request.form['email']

        # Check User already exists
        user = db.session.query(User).filter_by(email=form_email).first()

        if user:
            flash('You have already signed up with that email, log in instead', 'error')
            return render_template('login.html')
        else:
            hash_password = generate_password_hash(
                password=form_password,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                email=form_email,
                password=hash_password,
                name=form_name
            )
            db.session.add(new_user)
            db.session.commit()

            # Log in and authenticate user after adding details to database.
            login_user(new_user)

            user = db.session.query(User).filter_by(email=form_email).first()

            return render_template("home.html", current_user=current_user, users=user)
    return render_template("register.html", current_user=current_user)


@app.route('/home', methods=['GET', 'POST'])
def home():
    user = db.session.query(User).filter_by(id=current_user.id).first()
    task_list = db.session.query(Tasks).filter_by(user_id=current_user.id)
    return render_template("home.html", current_user=current_user, users=user, task_list=task_list)


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_task():

    if request.method == 'POST':
        if current_user.is_authenticated and request.form['taskname'] != '' and request.form['taskdate'] != '' and request.form['tasktime'] != '':
            new_task = Tasks(
                user_id=current_user.id,
                task_name=request.form['taskname'],
                task_date=request.form['taskdate'],
                task_time=request.form['tasktime'],
                task_priority=request.form['taskpriority'],
                task_status='OPEN'
            )
            db.session.add(new_task)
            db.session.commit()
    return redirect(url_for('home'))


@app.route('/delete/<int:task_id>', methods=["GET", "POST"])
@login_required
def delete(task_id):
    task_to_delete = Tasks.query.get(task_id)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/check/<int:task_id>', methods=["GET", "POST"])
@login_required
def check(task_id):
    task_to_update = Tasks.query.filter_by(id=task_id).first()
    task_to_update.task_status = 'CLOSED'
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/uncheck/<int:task_id>', methods=["GET", "POST"])
@login_required
def uncheck(task_id):
    task_to_update = Tasks.query.filter_by(id=task_id).first()
    task_to_update.task_status = 'OPEN'
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('logon'))


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True, host="localhost", port="5000")