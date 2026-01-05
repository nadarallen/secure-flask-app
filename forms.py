from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, ValidationError
from models import User

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=20),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username must contain only letters, numbers, and underscores.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$', message="Password must include at least one letter and one number.")
    ])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose another.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
