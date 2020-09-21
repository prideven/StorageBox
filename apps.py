import sys, os
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, current_app, \
    send_file
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, DateTime, func
from sqlalchemy.orm import sessionmaker
from DB_Setup import Base, StorageLogin, FileMetadata

from werkzeug.utils import secure_filename

apps = Flask(__name__)
apps.secret_key = '12345'

engine = create_engine('sqlite:///Storage.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


UPLOAD_FOLDER = '/Users/priyanka/Desktop'

apps.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'csv', 'xml'])
apps.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


@apps.route('/')
@apps.route('/home')
def index():
    return render_template('index.html')


@apps.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = session.query(StorageLogin).filter_by(email=email).first()

        if user and user.password == password:

            return render_template('profile.html')
        else:
            flash("Incorrect credentials")
            return render_template('login.html')

    else:

        return render_template('login.html')


@apps.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
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


@apps.route('/profile', methods=['GET', "POST"])
def profile():
    return render_template('profile.html')


@apps.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected for uploading')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(apps.config['UPLOAD_FOLDER'], filename))
            flash('File successfully uploaded')
            new_file = FileMetadata(file_name=filename, loc=UPLOAD_FOLDER)
            session.add(new_file)
            session.commit()

            return redirect('/profile')
        else:
            flash('Allowed file types are txt, pdf, csv, xml')
            return redirect(request.url)

    return render_template('uploadfile.html')


@apps.route('/view', methods=['GET', 'POST'])
def viewFile():

    files=session.query(FileMetadata).all()
    return render_template('Viewfile.html',files=files)


@apps.route('/ViewFile/<string:filename>/delete', methods=['GET', 'POST'])
def deletefile(filename):

    if request.method == 'POST':
        fileToDelete = session.query(FileMetadata).filter_by(file_name=filename).one()
        session.delete(fileToDelete)
        session.commit()
        print("file successfully deleted")
        return render_template('viewFile.html')
    else:
        return render_template('deletefile.html', file=filename)

@apps.route('/ViewFile/<string:filename>/edit', methods=['GET', 'POST'])
def downloadfile(filename):
    path=os.path.join(current_app.root_path, apps.config['UPLOAD_FOLDER'])
    return send_from_directory(directory=UPLOAD_FOLDER, filename=filename, as_attachment=True)


if __name__ == '__main__':
    apps.debug = True
    apps.run(host='127.0.0.1', port=5000)
