from flask_wtf import Form
from wtforms import validators, StringField, PasswordField
from wtforms.fields.html5 import EmailField
from flask import Flask, request

class RegisterForm(Form):
   name = StringField('Name', [validators.DataRequired()])
   email = EmailField('Email', [ validators.DataRequired()])
   username = StringField('Username', [
      validators.DataRequired(),
      validators.Length(min=4, max=25)
      ])
   password = PasswordField('Password',[validators.DataRequired()])


class LoginForm(Form):
    username = StringField('Username', [
      validators.DataRequired(),
      validators.Length(min=4, max=25)
      ])
    password = PasswordField('Password', [
      validators.DataRequired(),
      validators.Length(min=4, max=8)
      ])