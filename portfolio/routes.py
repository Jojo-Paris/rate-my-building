import string, secrets
from portfolio import app, mail, Message, func
from flask import render_template, redirect, url_for, flash, request
from portfolio.models import User, Review
from portfolio.forms import RegisterForm, LoginForm, UpdateEmailForm, ChangePasswordForm, ForgotPasswordForm, ResetPassword, ReviewForm
from portfolio import db
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
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
        return redirect(url_for('logged_in_page'))

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
                flash('Username or password not found. Please try again.', category='danger')
        else:
            flash('Username or password not found. Please try again.', category='danger')

    return render_template('login.html', form=form)

@app.route('/logout')
def logout_page():
    logout_user()
    flash("You have been logged out. See you again!", category='info')
    return redirect(url_for("home_page"))

@app.route('/logged-in-home')
@login_required
def logged_in_page():
    return render_template('logged_in.html')


@app.route('/update-email', methods=['GET', 'POST'])
@login_required
def update_email():
    form = UpdateEmailForm()
    if form.validate_on_submit():
        # Check if the email is already taken
        existing_user = User.query.filter_by(email_address=form.new_email.data).first()
        if existing_user:
            flash('That email is already taken. Please choose a different one.', category='danger')
            return render_template('update_email.html', form=form)
        
        # Update the email_address attribute of the current_user
        current_user.email_address = form.new_email.data
        # Commit the changes to the database
        db.session.commit()
        flash('Email updated successfully!', category='success')
        return redirect(url_for('account_info'))
    return render_template('update_email.html', form=form)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        # Update the user's password
        current_user.password = form.new_password.data
        db.session.commit()
        flash('Password changed successfully!', category='success')
        return redirect(url_for('account_info'))
    return render_template('change_password.html', form=form)

@app.route('/account-info')
@login_required
def account_info():
    return render_template('account_info.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password_page():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        send_email_form(form.email.data)
        return redirect(url_for('login_page'))
    return render_template('forgot_password.html', form=form)

@app.route('/reset-password/<token>/<email>', methods=['GET', 'POST'])
def password_not_logged_in_page(token, email):
    form = ResetPassword()
    if form.validate_on_submit():
        user = User.query.filter(func.lower(User.email_address) == func.lower(email)).first()

        if user:
            user.password = form.new_password.data
            db.session.commit() 
            flash('Password reset successfully!', category='success')
            return redirect(url_for('login_page'))
        else:
            flash('Invalid user or token.', category='error')

    return render_template('password_not_logged_in_page.html', form=form)


def send_email_form(email):

    token = generate_reset_token()
    msg = Message('Password Reset', sender='ratemybuilding0@gmail.com', recipients=[email])
    msg.body = f'Click the following link to reset your password: {url_for("password_not_logged_in_page", token=token, email=email, _external=True)}'

    try:
        mail.send(msg)
        flash('Password reset instructions sent to your email.', category='success')
    except Exception as e:
        flash('An error occurred while sending the email. Please try again later.', category='error')

def generate_reset_token(length=32):
    characters = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(characters) for _ in range(length))
    return token

@app.route('/review', methods=['GET', 'POST'])
def review_page():
    form = ReviewForm()

    if form.validate_on_submit():
        # Extract the review data from the form and save in database
        review_to_create = Review(
            buildingName = form.building.data,
            aesthetics = int(form.aesthetics.data),
            cleanliness = int(form.cleanliness.data),
            peripherals = int(form.peripherals.data),
            vibes = int(form.vibes.data),
            description = form.content.data,
            room = form.classroom_name.data,
            date_created = datetime.utcnow(),
            owner = current_user.id
        )

        db.session.add(review_to_create)
        db.session.commit()
        flash('Review submitted successfully!', category='success')
        return redirect(url_for('logged_in_page'))

    return render_template('review.html', form=form)

@app.route('/view-user-review/edit/<int:review_id>', methods=['GET', 'POST'])
def edit_user_review(review_id):
    review = Review.query.get_or_404(review_id)
    form = ReviewForm(obj=review)  # Populate the form with existing review data

    if form.validate_on_submit():
        # Update the review data
        review.buildingName = form.building.data
        review.aesthetics = int(form.aesthetics.data)
        review.cleanliness = int(form.cleanliness.data)
        review.peripherals = int(form.peripherals.data)
        review.vibes = int(form.vibes.data)
        review.description = form.content.data
        review.room = form.classroom_name.data

        db.session.add(review)
        db.session.commit()
        flash('Review updated successfully!', category='success')
        return redirect(url_for('view_user_review'))

    form.content.data = review.description  # Set the initial value for the content field
    return render_template('edit_review.html', form=form, review=review)



@app.route('/view-user-review')
def view_user_review():

    return render_template('user_reviews.html')    

@app.route('/delete_review/<int:id>')
def delete_review(id):
    review_to_delete = Review.query.get_or_404(id)
    
    try: 
        db.session.delete(review_to_delete)
        db.session.commit()
        flash("Review deleted successfully!", category='success')
        return redirect(url_for('view_user_review'))

    except:
        flash("Review not found or unable to delete.", category='error')
        return redirect(url_for('view_user_review'))