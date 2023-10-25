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