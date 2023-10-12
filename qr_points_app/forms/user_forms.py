from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Length, Email, EqualTo
from qr_points_app.models.user import User
from flask_wtf.file import FileField, FileAllowed

class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=1, max=60)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=1, max=60)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    photo = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'heic'], 'File does not have an approved extension: jpg, jpeg, png, heic')])


class GroupCodeForm(FlaskForm):
    code = StringField('Group Code', validators=[DataRequired()])
    submit = SubmitField('Enter Group')

class JoinGroupForm(FlaskForm):
    code = StringField('Group Code', validators=[DataRequired()])
    submit = SubmitField('Join Group')

class AdminRegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=20)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    admin_secret = StringField('Admin Secret', validators=[DataRequired()])
    submit = SubmitField('Sign Up as Admin')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')  
    submit = SubmitField('Login')
