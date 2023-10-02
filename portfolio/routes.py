from portfolio import app
from flask import render_template, redirect, url_for, flash, request
from portfolio.models import User, Review
from portfolio.forms import RegisterForm, LoginForm
from flask_login import logout_user, login_required


from portfolio import db
from flask_login import login_user, logout_user, login_required, current_user
import os

@app.route("/")
@app.route("/home")
def home_page():
    return render_template('home.html')

@app.route("/register", methods=['POST', 'GET'])
def register_page():

    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(
            username = form.username.data,
            firstName = form.firstName.data,
            lastName = form.lastName.data,
            email_address = form.email_address.data,
            password = form.password1.data
        )

        db.session.add(user_to_create)
        db.session.commit()

        login_user(user_to_create)
        flash(f"Account created successfully! You are now logged in as {user_to_create.username}", category='success')
        return redirect(url_for('home_page'))

    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}', category='danger')

    return render_template('register.html', form=form)

@app.route("/login", methods=['POST', 'GET'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user:
            if attempted_user.check_password_correction(attempted_password=form.password.data):
                login_user(attempted_user)
                flash(f'Welcome, {attempted_user.username}!', category='success')
                return redirect(url_for('logged_in_page'))
            else:
                flash('Incorrect password. Please try again.', category='danger')
        else:
            flash('Username not found. Please check and try again.', category='danger')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout_page():
    logout_user()
    flash("You have been logged out. See you again!", category='info')
    return redirect(url_for("home_page"))