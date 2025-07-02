from flask_wtf import FlaskForm as FF
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, ValidationError, Email
import re
from flask_bcrypt import Bcrypt

# Initialize Bcrypt once for use in validators
bcrypt = Bcrypt()

# Custom validation functions
def name_val(form, field):
    if not re.match(r"^[a-zA-Z\s]+$", field.data):
        raise ValidationError('Name should contain only letters and spaces')

def number_val(form, field):
    # Remove all non-digit characters except +
    cleaned = re.sub(r'[^\d\+]', '', field.data)
    # Allow +977 or no country code, but enforce 10 digits after stripping country code
    if not re.match(r'^(\+977)?\d{10}$', cleaned):
        raise ValidationError("Phone number must be exactly 10 digits (with or without +977)")
    # Check length without country code
    digits_only = re.sub(r'^\+977', '', cleaned)
    if len(digits_only) != 10:
        raise ValidationError("Phone number must be exactly 10 digits")

def pw_val(form, field):
    # TODO: Remove print statement in production
    print("Password entered:", field.data)  # Debugging line
    if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", field.data):
        raise ValidationError("Password must be at least 8 characters with uppercase, lowercase, digits, and special characters")

def no_previous_password(form, field):
    if hasattr(form, 'meta') and 'current_password_hash' in form.meta and form.meta['current_password_hash']:
        if bcrypt.check_password_hash(form.meta['current_password_hash'], field.data):
            raise ValidationError("You cannot reuse your previous password. Please choose a new one.")

# Form classes
class RegistrationForm(FF):
    full_name = StringField('Full Name', validators=[DataRequired(), name_val])
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    phone_num = StringField('Phone Number', validators=[DataRequired(), number_val])
    address = StringField('Address', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), pw_val])
    confirm_pw = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

class LoginForm(FF):
    email_or_phone = StringField('Email or Phone', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

    def validate_email_or_phone(self, field):
        email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        phone_cleaned = re.sub(r'[^\d\+]', '', field.data)
        phone_pattern = r'^(\+977)?\d{10}$'
        if not re.match(email_pattern, field.data) and not re.match(phone_pattern, phone_cleaned):
            raise ValidationError("Enter a valid email or 10-digit phone number (with or without +977)")
        if re.match(phone_pattern, phone_cleaned):
            digits_only = re.sub(r'^\+977', '', phone_cleaned)
            if len(digits_only) != 10:
                raise ValidationError("Phone number must be exactly 10 digits")

class ForgotPasswordForm(FF):
    identifier = StringField('Email or Phone Number', validators=[DataRequired()])
    submit = SubmitField('Request Reset')

    def validate_identifier(self, field):
        email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        phone_cleaned = re.sub(r'[^\d\+]', '', field.data)
        phone_pattern = r'^(\+977)?\d{10}$'
        if not re.match(email_pattern, field.data) and not re.match(phone_pattern, phone_cleaned):
            raise ValidationError("Enter a valid email or 10-digit phone number (with or without +977)")
        if re.match(phone_pattern, phone_cleaned):
            digits_only = re.sub(r'^\+977', '', phone_cleaned)
            if len(digits_only) != 10:
                raise ValidationError("Phone number must be exactly 10 digits")

class ResetPasswordForm(FF):
    new_password = PasswordField('New Password', validators=[DataRequired(), pw_val, no_previous_password])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Reset Password')