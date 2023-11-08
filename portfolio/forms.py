from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DecimalField, IntegerField, validators
from wtforms.validators import Length, EqualTo, Email, DataRequired, ValidationError, NumberRange
from portfolio.models import User
from flask_login import current_user

class RegisterForm(FlaskForm):

    def validate_username(self, username_to_check):
        user = User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a different username')

    def validate_email_address(self, email_address_to_check):
        email_address = User.query.filter_by(email_address=email_address_to_check.data).first()
        if email_address:
            raise ValidationError('Email Address already exists! Please try a different email address')
        
    firstName = StringField(label='First Name:', validators=[Length(min=2, max=30), DataRequired()])
    lastName = StringField(label='Last Name:', validators=[Length(min=2, max=30), DataRequired()])
    username = StringField(label='User Name:', validators=[Length(min=3, max=30), DataRequired()])
    email_address = StringField(label='Email Address:', validators=[Email(), DataRequired()])
    password1 = PasswordField(
        label='Enter Password:',
        validators=[
            validators.Length(min=8, message="Password must be at least 8 characters long."),
            validators.Regexp(r'^(?=.*\d)', message="Password must contain at least one number."),
            validators.DataRequired(message="Password is required."),
        ])
    
    password2 = PasswordField(label='Confirm Password:', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Create Account')