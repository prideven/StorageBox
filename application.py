import sys, os
from datetime import datetime

import boto3
from boto3 import resource
from flask import Flask, render_template, request, redirect, url_for,Response, flash, session, send_from_directory, current_app, \
    send_file,g
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, DateTime, func
from sqlalchemy.orm import sessionmaker
from DB_Setup import Base, StorageLogin, FileMetadata
from werkzeug.utils import secure_filename
from flask_restful import Resource,Api

from boto.s3.key import Key
from boto3.dynamodb.conditions import Key



aws_access_key_id = os.environ.get("aws_access_key_id")
if not aws_access_key_id:
    raise ValueError("No aws_access_key_id secret key set for storageBox")

aws_secret_access_key = os.environ.get("aws_secret_access_key")
if not aws_secret_access_key:
    raise ValueError("No aws_secret_access_key secret key set for StorageBox")

EndPoint = os.environ.get("EndPoint")
if not EndPoint:
    raise ValueError("No END Point set  for StorageBox")

BucketName = os.environ.get("BucketName")
if not BucketName:
    raise ValueError("No Bucket set for StorageBox")

S3Host  = os.environ.get("S3Host")
if not S3Host:
    raise ValueError("No S3 HOST set for StorageBox")



application = Flask(__name__)
api=Api(application)
application.secret_key = '12345'


engine = create_engine('sqlite:///Storage.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
sess = DBSession()

# for local storage

UPLOAD_FOLDER = '/Users/priyanka/Desktop'
local_env=True

application.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'csv', 'xml','xls','doc'])
application.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


@application.route('/')
@application.route('/home')
def index():
    return render_template('index.html')


@application.route('/login', methods=['GET', 'POST'])
def login():

    if local_env:
        if 'user_name' in session:
            return render_template('index.html')
        else:
            if request.method == "POST":
                name = request.form.get('username')
                dynamodb_resource = resource('dynamodb', region_name=EndPoint)
                table = dynamodb_resource.Table('users')
                response = table.query(KeyConditionExpression=Key('username').eq(name))
                items = response['Items']
                if items:
                    if check_password_hash(items[0]['password'], request.form.get('password')):
                        session['user_name'] = items[0]['username']
                        session['email_id'] = items[0]['email']
                        # session['fullname'] = items[0]['fullname']
                        if 'next' in session:
                            next = session.get('next')
                            session.pop('next')
                            return redirect(next)
                        else:
                            return redirect(url_for('profile'))
                else:
                    flash("Incorrect Username and Password")
                    return render_template('login.html')
            else:
                return render_template('login.html')







    else:
        if request.method == 'POST':

            session.pop('id',None)
            email = request.form.get('email')
            password = request.form.get('password')
            user = sess.query(StorageLogin).filter_by(email=email).first()

            if user and user.password == password:
                session['id']=user.email
                return redirect(url_for('profile'))
            else:
                flash("Incorrect credentials")
                return render_template('login.html')
        else:
            return render_template('login.html')


@application.route('/signup', methods=['GET', 'POST'])
def signup():
    if local_env:
        if 'user_name' in session:
            return render_template('index.html')
        else:
            name = request.form.get('username')
            if request.method == "POST":

                password_hash= generate_password_hash(request.form.get('password'))

                dyno_resource = resource('dynamodb', region_name=EndPoint)

                dyno_table = dyno_resource.Table('users')

                response = dyno=dyno_table.query(KeyConditionExpression=Key('username').eq(name))
                items = response['Items']
                if items:
                    flash('User already exists, Enter another user')
                    return render_template('signup.html')
                else:
                    response = dyno_table.put_item(
                        Item={
                            'username': name,
                            'email': request.form.get('email'),
                            'password': password_hash
                        }
                    )
                    return redirect(url_for('login'))
            return render_template('signup.html')



    else:

        if request.method == "POST":
            email = request.form.get('email')
            name = request.form.get('username')
            password = request.form.get("password")

            user = sess.query(StorageLogin).filter_by(email=email).first()
            if user:
                flash("User already exists")
                return redirect(url_for('signup'))

            new_user = StorageLogin(email=email, username=name, password=password)
            sess.add(new_user)
            sess.commit()
            return redirect(url_for('login'))
        else:
            return render_template('signup.html')


@application.route('/logout')
def signout():

    if local_env:
        session.pop('user_name',None)
        session.pop('mail_id',None)

        #    session.pop('screen_name', None)
        return render_template('index.html')

    else:
        session.pop('id', None)
        return render_template('signOut.html')

@application.route('/profile', methods=['GET'])
def profile():
    if local_env:
        if 'user_name' in session:
            return render_template('profile.html', name=session['user_name'])

        else:
            return render_template('login.html')

    else:
        if 'id' not in session:
            return render_template('login.html')
        id=session["id"]
        user=sess.query(StorageLogin).filter_by(email=id).one()
        return render_template('profile.html', name=user.username)


def upload_to_S3(file, BucketName,description):
    k = Key(BucketName)
    k.key = session['user_name'] + '/' + file.filename

    date = duplicate_file_check(k.key, BucketName)
    s3 = boto3.client("s3", aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    try:
        s3.upload_fileobj(
            file,
            BucketName,
            k.key,
            ExtraArgs={

                "ContentType": file.content_type,

                "Metadata": {"creation_date": date}

            }
        )
    except Exception as e:
        flash("Error in file upload!: ", e)
        return e
    filename = file.filename
    dynomodb=boto3.resource('dynamodb')
    dynamodb_resource = resource('dynamodb', region_name=EndPoint)
    dyno_table = dynamodb_resource.Table('metadata')

    if True:
        dyno_table.put_item(
            Item={
                'filename': filename,
                'description': description
                 #"Created": datetime.utcnow().isoformat(),

            }
        )

    return "Your File is successfully Uploaded in StorageBox"


def file_list():
    User_name = session['user_name'] + '/'
    s3 = boto3.client("s3", aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    s3_resource = boto3.resource('s3')
    my_bucket = s3_resource.Bucket(BucketName)


    result = my_bucket.objects.filter(Prefix=User_name)
    Filemetadata = {}
    fileList = []
    for v in result:
        Filemetadata = metadata_creation(v.key)
        fileList.append(Filemetadata)
    return fileList


def metadata_creation(filename):

    s3 = boto3.client("s3", aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    metadata_list = {}

    dynamodb_resource = resource('dynamodb', region_name=EndPoint)
    table = dynamodb_resource.Table('metadata')
    file=filename.split('/',1)[1]
    response = table.query(KeyConditionExpression=Key('filename').eq(file))
    items = response['Items']



    response= s3.head_object(Bucket=BucketName, Key=filename)
    metadata_list['modified'] = response["LastModified"]
    metadata_list['file_name'] = filename.split('/',1)[1]
    if items:

        metadata_list['description']= items[0]['description']

    else:
        metadata_list['description']="No"

    try:
        metadata_list['created'] = response['ResponseMetadata']['HTTPHeaders']['x-amz-meta-creation_date']
    except:
        metadata_list['created'] = 'Not Specified'

    return metadata_list


@application.route('/upload', methods=['GET', 'POST'])
def upload():
    if local_env:
        if request.method == "POST":
            if 'file' not in request.files:
                flash('No file')
                return redirect(request.url)
            file = request.files['file']
            if file.filename == '':
                flash('No file selected')
                return redirect(request.url)
            
            filename = session['user_name'] + '/' + file.filename
            description= request.form['File_description']
            file.filename = secure_filename(filename)
            out=upload_to_S3(file,BucketName,description)
            result = file_list()
            return render_template('ViewFile.html', files=result)
        return render_template('uploadfile.html')

    else:  #to run locally

        if 'id' not in session:
            return render_template('login.html')
        if request.method == 'POST':
            # check done to see if post request has the file
            if 'file' not in request.files:
                flash('No file')
                return redirect(request.url)
            file = request.files['file']
            if file.filename == '':
                flash('No file selected')
                return redirect(request.url)
            if file:
                filename = secure_filename(file.filename)
                file.save(os.path.join(application.config['UPLOAD_FOLDER'], filename))
                flash('File successfully uploaded')
                id=session['id']
                new_file = FileMetadata(file_name=filename, mail_id=id)
                sess.add(new_file)
                sess.commit()

                return redirect('/profile')
            else:
                flash('Allowed file types are txt, pdf, csv, xml')
                return redirect(request.url)

        return render_template('uploadfile.html')


def duplicate_file_check(filename, bucket_name):
    s3 = boto3.client("s3", aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    s3 = boto3.resource('s3')
    s3_bucket = s3.Bucket(bucket_name)
    objects = list(s3_bucket.objects.filter(Prefix=filename))
    if len(objects) > 0 and objects[0].key == filename:
       Filemetadata = metadata_creation(filename)
       date = Filemetadata['created']
       return date
    else:
       current = datetime.now()
       date = str(current)
       return date



@application.route('/view', methods=['GET'])
def viewFile():

    if local_env:
        if session['user_name'] == 'admin':
            result = admin_files()
            return render_template('Viewfile.html', files=result)
        else:
            result = file_list()
            return render_template('Viewfile.html', files=result)



    if 'id' not in session:
        return render_template('login.html')
    id = session['id']
    files=sess.query(FileMetadata).filter_by(mail_id=id)
    return render_template('Viewfile.html',files=files)


@application.route('/ViewFile/<string:filename>/delete', methods=['GET', 'POST'])
def deletefile(filename):

    if local_env:
        if request.method == 'POST':

            filename = session['user_name'] + '/' + filename
            s3 = boto3.client("s3", aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
            s3.delete_object(Bucket=BucketName, Key=filename)

            dynamodb_resource = resource('dynamodb', region_name=EndPoint)

            table = dynamodb_resource.Table('metadata')
            file = filename.split('/', 1)[1]

            response = table.query(KeyConditionExpression=Key('filename').eq(file))
            items = response['Items']

            if items:

                dynamo_resource = resource('dynamodb', region_name=EndPoint)

                response = table.delete_item(Key={
            'filename': file,
        },
    )

            result = file_list()
            return render_template('viewFile.html',files=result)


            key_name = request.args['filename']
            s3 = boto3.client("s3", aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
            s3.delete_object(Bucket=BucketName, Key=key_name)
            result = file_list()
            return render_template('viewFile.html', files=result)
        else:
            return render_template('deleteFile.html', file=filename)

    else:

        #if 'id' not in session:
            #return render_template('login.html')

        if request.method == 'POST':
            os.remove(os.path.join(application.config['UPLOAD_FOLDER'],filename))
            fileToDelete = sess.query(FileMetadata).filter_by(file_name=filename).one()
            sess.delete(fileToDelete)
            sess.commit()
            print("file successfully deleted")
            return render_template('viewFile.html')
        else:
            return render_template('deletefile.html', file=filename)




@application.route('/ViewFile/<string:filename>/edit', methods=['GET', 'POST'])
def editfile(filename):

    if True:
        if request.method == 'POST':

            dynamodb_resource = resource('dynamodb', region_name=EndPoint)
            table = dynamodb_resource.Table('metadata')
            response = table.query(KeyConditionExpression=Key('filename').eq(filename))
            items = response['Items']

            if items:
                table.update_item(
                    Key={
                        'filename': filename,
                    },
                    UpdateExpression="set description = :g",
                    ExpressionAttributeValues={
                        ':g': request.form.get('update')
                    },
                    ReturnValues="UPDATED_NEW"
                )
                #items[0]['description'] = request.form.get('updated_description')


            result = file_list()
            return render_template('viewFile.html',files=result)
        else:
            return render_template('edit.html',file=filename)








@application.route('/View/<string:filename>/edit', methods=['GET', 'POST'])
def downloadfile(filename):

    if local_env:
        filename = session['user_name'] + '/' + filename
        s3 = boto3.client("s3", aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        file = s3.get_object(Bucket=BucketName, Key=filename)
        print(file)
        return Response(file['Body'].read(), headers={"Content-Disposition": "attachment; filename=%s" % filename})


    else:
        if 'id' not in session:
            return render_template('login.html')
        path = os.path.join(current_app.root_path, application.config['UPLOAD_FOLDER'])
        return send_from_directory(directory=UPLOAD_FOLDER, filename=filename, as_attachment=True)

def admin_files():
    s3 = boto3.client("s3", aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    resource = boto3.resource('s3')
    bucket = resource.Bucket(BucketName)
    result = bucket.objects.filter()
    file_list=print_files(result)
    return file_list


def print_files(result):

     Filemetadata = {}
     file_list = []

     for v in result:
          Filemetadata = metadata_creation(v.key)
          file_list.append(Filemetadata)
     return file_list


if __name__ == '__main__':
    application.debug = True
    application.run(host='127.0.0.1', port=5000)
