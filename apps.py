import sys,os
from flask import Flask, render_template, request, redirect, url_for,flash,session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from DB_Setup import Base,StorageLogin


apps=Flask(__name__)

apps.secret_key = '12345'

engine = create_engine('sqlite:///Storage.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

users = StorageLogin(username="Priyanka",email="prideven@gmail.com",password="ppppp")
session.add(users)
session.commit()

@apps.route('/')
@apps.route('/home')
def index():
    return render_template('index.html')



@apps.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user=session.query(StorageLogin).filter_by(email=email).first()

        if user and user.password == password:

            return render_template('profile.html')
        else:
            return render_template('login.html')

    else:

        return render_template('login.html')


@apps.route('/signup', methods=['GET','POST'])
def signup():
    if request.method=="POST":
        email = request.form.get('email')
        name = request.form.get('username')
        password = request.form.get("password")

        user = session.query(StorageLogin).filter_by(email=email).first()
        if user:
            flash("User already exists")
            return redirect(url_for('signup'))

        new_user = StorageLogin(email=email, username=name, password=password)
        session.add(new_user)
        session.commit()
        return redirect(url_for('login'))
    else:
        return render_template('signup.html')

@apps.route('/profile', methods=['GET',"POST"])
def profile():
    return render_template('profile.html')




if __name__ == '__main__':
    apps.debug = True
    apps.run(host='127.0.0.1', port=5000)










