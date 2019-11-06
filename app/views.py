from app import app, lm
from flask import request, redirect, render_template, url_for, flash
from flask_login import login_user, logout_user, login_required
#from flask_paginate import Pagination, get_page_parameter
from .forms import LoginForm, RegistrationForm, CreateSENDForm
from .user import User
from werkzeug.security import generate_password_hash
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from flask_table import Table, Col


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # This will allow the user to login to the system.
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = app.config['USERS_COLLECTION'].find_one({"_id": form.username.data})
       # If the user is validated, it will flash successful
        if user and User.validate_login(user['password'], form.password.data):
            user_obj = User(user['_id'])
            login_user(user_obj)
            flash("Logged in successfully!", category='success')
            return redirect(request.args.get("next") or url_for("write"))
        # Else it will deny access
        flash("Wrong username or password!", category='error')
    return render_template('login.html', title='login', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    # Connect to the DB
    form = RegistrationForm()

    if request.method == 'POST' and form.validate_on_submit():
        collection = MongoClient()["blog"]["users"]
        # Ask for data to store
        username = form.username.data
        password = form.password.data
        pass_hash = generate_password_hash(password, method='pbkdf2:sha256')

        # Insert the user in the DB
        try:
            collection.insert_one({"_id": username, "password": pass_hash})
            flash("Username created!", category='success')
            return redirect(url_for('login'))
        except DuplicateKeyError:
            flash("Username already exists!", category='warning')
            return redirect(url_for('register'))
    return render_template('register.html', form=form)


@app.route('/createsend', methods=['GET', 'POST'])
@login_required
def createsend():
    # Connect to the DB
    form = CreateSENDForm()

    if request.method == 'POST' and form.validate_on_submit():
        collection = MongoClient()["blog"]["sendlist"]
        # Ask for data to store
        send_title = form.send_title.data
        send_acro = form.send_acro.data
        send_explanation = form.send_explanation.data

        # Insert the user in the DB
        try:
            collection.insert_one({"send_title": send_title, "send_acro": send_acro, "send_explanation": send_explanation})
            flash("SEND Category Successfully added!", category='success')
            return redirect(url_for('createsend'))
        except DuplicateKeyError:
            flash("SEND Category already exists!", category='warning')
            return redirect(url_for('createsend'))
    return render_template('createsend.html', form=form)

@app.route('/viewsend')
def viewsend():
    collection = MongoClient()["blog"]["sendlist"]

    # Declare your table
    class SendTable(Table):
        send_title = Col('send_title')
        send_acro = Col('send_acro')
        send_explanation = Col('send_explanation')




    results = collection.find({})

    #return render_template('viewsend.html', table=table, table2=table2, results=results)

    






@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/write', methods=['GET', 'POST'])
@login_required
def write():
    return render_template('write.html')


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    return render_template('settings.html')


@lm.user_loader
def load_user(username):
    u = app.config['USERS_COLLECTION'].find_one({"_id": username})
    if not u:
        return None
    return User(u['_id'])
