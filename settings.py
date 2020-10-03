import os
basedir = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = os.environ.get('SECRET_KEY') or 'SuperSecretKeys'
MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.googlemail.com')
MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
DEBUG = True
TEST_DYNAMO_TABLE = 'Users'
PROD_DYNAMO_TABLE = 'Users_dev'