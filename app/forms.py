from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, validators

class LoginForm(FlaskForm):
    """Login form to access writing and settings pages"""

    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])

class RegistrationForm(FlaskForm):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('New Password', [validators.DataRequired()])
    confirm = PasswordField('Repeat Password', 
        [validators.DataRequired(),validators.EqualTo('password', message='Passwords must match')])

class CreateSENDForm(FlaskForm):
    send_title = StringField('SEND Name', [validators.DataRequired()])
    send_acro = StringField('Acronym')
    send_explanation = TextAreaField('Explanation',[validators.optional(), validators.length(max=200)])
