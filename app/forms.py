from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(min=2, max=50)])
    userName = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    fullName = StringField('Fullname', validators=[DataRequired(), Length(min=2)])
    contact = StringField('Contact', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=12)])
    pass2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    confirmBtn = SubmitField('Sign Up')
    
