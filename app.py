import re
from flask import Flask, redirect, url_for, render_template, request
from config import Config
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from flask.helpers import flash
from datetime import datetime, timedelta
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import logout_user
from werkzeug.urls import url_parse
from flask_login import current_user, login_user
from flask_login import login_required
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from flask_moment import Moment
import time




#SQL: structured date #NoSQL: non structured data
app = Flask(__name__)
today = date.today()
db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'
moment = Moment(app)

#use migrate when you need to change the existing data in database, so you can store in other database
app.config.from_object(Config) #config is the file and Config is the class imported
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Todo.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
# app.config['SQLALCHEMY_BINDS'] = {'two': 'sqlite:///two.sqlite3', 'three': 'sqlite:///three.sqlite3'}
app.secret_key = "hello"




class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()]) #first argument is name, and second argument is validating that the data is not sent empty
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    greenTasks = db.relationship('Todo', backref='owner', lazy='dynamic')
    yellowTasks = db.relationship('two', backref='owner', lazy='dynamic')
    redTasks = db.relationship('three', backref='owner', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)   

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __init__(self, content):
        self.content = content

class two(db.Model):
    # __bind_key__ = 'two'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))#foreign key
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __init__(self, content):
        self.content = content

class three(db.Model):
    # __bind_key__ = 'three'
    id = db.Column(db.Integer, primary_key=True)
    answer = db.Column(db.String(200), nullable=False)
    user_id =  db.Column(db.Integer, db.ForeignKey('user.id'))
    emoji = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __init__(self, answer, emoji):
        self.answer = answer
        self.emoji = emoji


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')



@login.user_loader
def load_user(id):
    return User.query.get(int(id))
    

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are a user now!!!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit(): #if it is POST
        user = User.query.filter_by(username = form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data) 
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            return redirect(url_for('home'))
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)
    
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main'))


@app.route("/getTime", methods=['GET'])
def getTime():
    print("browser time: ", request.args.get("time"))
    print("server time : ", time.strftime('%A %B, %d %Y %H:%M:%S'));
    return "Done"


@app.route("/", methods = ["POST", "GET"]) #methods override only get requests
#post method sends info to the server, while get method sends info to client
def home():
    if request.method == "POST":
        value = request.form["submit_button"]
        if value == "binge":
            return redirect(url_for("red"))
        elif value == "uptick":
            return redirect(url_for("yellow"))
        elif value == "coldturkey":
            return redirect(url_for("green"))
    else:
        return render_template("home.html", date = today)

@app.route("/main", methods = ["POST", "GET"])
def main():
    if request.method == "POST":
        value = request.form["submit_button"]
        if value == "join":
            return redirect(url_for("register"))
    return render_template("main.html")



@app.route("/red", methods = ["POST", "GET"])
@login_required #protects the webpage, so that means need to log in before access
def red():
    if request.method == "POST":
        value = request.form["return"]
        if value == "submit":
            flash("Your answer is noted!!")
            answer = request.form["answer"]
            if answer == "Yes":
                emotion = request.form["emotion"]


                new_answer = three(answer, emoji=emotion)
                try:
                    db.session.add(new_answer)
                    db.session.commit()
                    return redirect(url_for("red"))
                except:
                    return "addition task for binge doesn't work"
            else:
                return redirect(url_for("red"))
        else:
            return redirect(url_for("home"))
    return render_template("red.html", binges = three.query.all())

i = 0
@app.route("/green", methods = ["POST", "GET"])
def green():
    if request.method == "POST":
        value = request.form["return"]
        if value == "Add this rule":
            content = request.form['r&d']
            new_task = Todo(content=content)
            try:
                db.session.add(new_task)
                flash("added.")
                db.session.commit()
                return redirect(url_for("green"))
            except:
                return 'There was an issue adding r&d'
            '''
            found_user = three.query.filter_by(date = today).first()
            if found_user != None:
                flash("It seems like you are done binging. Great Job! Are you free now to write some notes about your experience?")
                if request.method == "POST":
                    bingevalue = request.form['binge']
                    if bingevalue == "yes":
                        return render_template("bingenotes.html")
                    else:
                        return redirect(url_for("green"))
                else:
                    return redirect(url_for("green"))
            else:
                 return redirect(url_for("green"))
            '''
        else:
            return redirect(url_for("home"))
    else:
        return render_template("green.html", values=Todo.query.all())

@app.route("/yellow", methods = ["POST", "GET"])
def yellow():
    if request.method == "POST":
        value = request.form["return"]
        if value == "Add the nuisance":
            content = request.form["nuisances"]
            new_nuisance = two(content=content)
            try:
                db.session.add(new_nuisance)
                flash("added.")
                db.session.commit()
                return redirect(url_for("yellow"))
            except:
                return 'There was an issue adding r&d'

        else:
            return redirect(url_for("home"))
    else:
        return render_template("yellow.html", values=two.query.all())


@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)
    try:
        db.session.delete(task_to_delete)
        flash("deleted.")
        db.session.commit()
        return redirect(url_for("green"))
    except:
        return 'There was a problem deleting the task'


@app.route('/deleteYel/<int:id>')
def deleteYel(id):
    task_to_delete = two.query.get_or_404(id)
    try:
        db.session.delete(task_to_delete)
        flash("deleted.")
        db.session.commit()
        return redirect(url_for("yellow"))
    except:
        return 'There was a problem deleting the task'

@app.route('/deleteRed/<int:id>')
def deleteRed(id):
    task_to_delete = three.query.get_or_404(id)
    try:
        db.session.delete(task_to_delete)
        flash("Your binge date was deleted.")
        db.session.commit()
        return redirect(url_for("red"))
    except:
        return 'There was a problem deleting the task'


if __name__ == "__main__":
    db.create_all()
    # db.create_all(bind='two')
    # db.create_all(bind='three')
    app.run(debug=True)