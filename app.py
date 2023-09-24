from flask import Flask, render_template, request, redirect, Response, flash, url_for
from flask_sqlalchemy import SQLAlchemy
import io, os
from flask_bootstrap import Bootstrap
from flask_mail import Mail, Message
from itsdangerous import TimedSerializer
#from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, current_user, login_required, logout_user
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask_migrate import Migrate
import pyclamd
from pyclamd import ConnectionError
from forms.forms import *
import logging
import secrets
import sys
from gunicorn.app.wsgiapp import run
import os
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import NoCredentialsError
from botocore.exceptions import ClientError

SECRET_KEY = os.getenv('SECRET_KEY')
AWS_REGION = os.getenv('AWS_REGION')
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_SESSION_TOKEN = os.getenv('AWS_SESSION_TOKEN')
# Initialize Boto3 S3 client
s3 = boto3.client('s3', region_name=AWS_REGION)
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
user_table = dynamodb.Table('tan-dark-goshawkCyclicDB')


basedir = os.path.abspath(os.path.dirname(__file__))
secret_key = secrets.token_hex(16)


app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = secret_key
app.config['UPLOAD_FOLDER'] = 'uploads'

migrate = Migrate(app, dynamodb) 
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__) 


app.config["DYNAMODB_HOST"] = "http://localhost:8000"
app.config["DYNAMODB_AWS_ACCESS_KEY_ID"] = AWS_ACCESS_KEY_ID
app.config["DYNAMODB_AWS_SECRET_ACCESS_KEY"] = AWS_SECRET_ACCESS_KEY
app.config["DYNAMODB_READ_CAPACITY_UNITS"] = 10
app.config["DYNAMODB_WRITE_CAPACITY_UNITS"] = 10

# Configure mail server
MAIL_SERVER = os.getenv('MAIL_SERVER')
MAIL_PORT = os.getenv('MAIL_PORT')
MAIL_USE_TLS = os.getenv('MAIL_USE_TLS')
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
# MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')

app.config['MAIL_SERVER'] = MAIL_SERVER
app.config['MAIL_PORT'] = MAIL_PORT
app.config['MAIL_USE_TLS'] = MAIL_USE_TLS

# app.config['MAIL_DEFAULT_SENDER'] = MAIL_DEFAULT_SENDER
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD

mail = Mail(app)

class User(UserMixin):
    def __init__(self, user_id, username, email, password_hash, role_id):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role_id = role_id
    @staticmethod
    def create(user_id, username, email, password_hash, role_id):
        # Create a new user in DynamoDB
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('tan-dark-goshawkCyclicDB')

        try:
            table.put_item(
                Item={
                    'user_id': user_id,
                    'username': username,
                    'email': email,
                    'password_hash': password_hash,
                    'role_id': role_id
                }
            )
        except ClientError as e:
            # Handle any exceptions here
            print("Error creating user:", e)

    @staticmethod
    def get(user_id):
        # Retrieve user from DynamoDB
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('tan-dark-goshawkCyclicDB')

        try:
            response = table.get_item(
                Key={'user_id': user_id}
            )
            user_data = response.get('Item', None)
            return User(**user_data) if user_data else None
        except ClientError as e:
            # Handle any exceptions here
            print("Error getting user:", e)
            return None
    @staticmethod
    def get_by_email(email):
        # Query DynamoDB for a user by email (if you have a GSI on email)
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('tan-dark-goshawkCyclicDB')

        try:
            response = table.query(
                IndexName='email-index',  # Replace with your GSI name
                KeyConditionExpression=Key('email').eq(email)
            )
            user_data = response.get('Items', [])[0] if response.get('Items') else None
            return User(**user_data) if user_data else None
        except ClientError as e:
            # Handle any exceptions here
            print("Error getting user by email:", e)
            return None       
    @staticmethod
    def get(role_id):
        response = user_table.get_item(Key={'role_id': role_id})
        role_data = response.get('Item', None)
        return Role(**role_data) if role_data else None
    
    def __init__(self, user_name, email, password,role_id):
        self.user_name = user_name
        self.email = email
        self.password_hash = generate_password_hash(password)
        self.role_id = role_id  # Initialize with no role

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_password_reset_token(self, token_length=32, expiration_hours=1):
        token = secrets.token_urlsafe(token_length)
        self.password_reset_token = token
        expiration_time = datetime.utcnow() + timedelta(hours=expiration_hours)
        self.password_reset_expiration = expiration_time.strftime('%Y-%m-%dT%H:%M:%SZ')

        # Update the DynamoDB record
        user_table.update_item(
            Key={'user_id': self.user_id},
            UpdateExpression='SET password_reset_token = :token, password_reset_expiration = :expiration',
            ExpressionAttributeValues={
                ':token': token,
                ':expiration': self.password_reset_expiration
            }
        )

        return token

    def token_expired(self):
        if self.password_reset_expiration is None:
            return True  # Token expiration is not set

        current_time = datetime.utcnow()
        expiration_time = datetime.strptime(self.password_reset_expiration, '%Y-%m-%dT%H:%M:%SZ')
        return current_time > expiration_time

    @classmethod
    def get(cls, user_id):
        response = user_table.get_item(Key={'user_id': user_id})
        user_data = response.get('Item', None)

        if user_data:
            user = cls(user_id)
            user.password_reset_token = user_data.get('password_reset_token')
            user.password_reset_expiration = user_data.get('password_reset_expiration')
            return user
        else:
            return None


class Role:
    def __init__(self, role_id, role_name):
        self.role_id = role_id
        self.role_name = role_name
        
def get_user_by_username(username):
    response = dynamodb.get_item(
        TableName='tan-dark-goshawkCyclicDB',
        Key={'user_id': {'S': username}}
    )
    user_data = response.get('Item', None)
    return user_data

def authenticate(username, password):
    user_data = get_user_by_username(username)
    if user_data and user_data.get('password_hash', {}).get('S') == hashed_password(password):
        return user_data
    return None
    
    

class File:
    def __init__(self, id, filename, user_id, upload_time, file_size, comment):
        self.id = id
        self.filename = filename
        self.user_id = user_id
        self.upload_time = upload_time
        self.file_size = file_size
        self.comment = comment

    def save_to_dynamodb(self):
        response = table.put_item(
            Item={
                'id': self.id,
                'filename': self.filename,
                'user_id': self.user_id,
                'upload_time': self.upload_time,
                'file_size': self.file_size,
                'comment': self.comment
            }
        )
        return response

    @staticmethod
    def get_by_id(file_id):
        response = table.get_item(
            Key={'id': file_id}
        )
        item = response.get('Item', None)
        if item:
            return File(
                id=item['id'],
                filename=item['filename'],
                user_id=item['user_id'],
                upload_time=item['upload_time'],
                file_size=item['file_size'],
                comment=item['comment']
            )
        return None

    @staticmethod
    def get_all_by_user(user_id):
        response = table.query(
            IndexName='user_id_index',  # Replace with your index name
            KeyConditionExpression=Key('user_id').eq(user_id)
        )
        items = response.get('Items', [])
        return [File(
            id=item['id'],
            filename=item['filename'],
            user_id=item['user_id'],
            upload_time=item['upload_time'],
            file_size=item['file_size'],
            comment=item['comment']
        ) for item in items]
    
def has_admin_privileges(user_data):
    return user_data and user_data.get('role_name', {}).get('S') == 'admin'

def has_editor_privileges(user_data):
    return user_data and user_data.get('role_name', {}).get('S') == 'editor'



    
    
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(username):
    user_data = get_user_by_username(username)
    if user_data:
        user = User()
        user.id = username
        return user
    return None

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# default routes
@app.route('/', methods=["GET", "POST"])
def index():
    # Assuming your DynamoDB table stores file information
    response = user_table.scan()
    items = response.get('Items', [])
    
    # Transform DynamoDB items into a list of dictionaries
    files = [{'filename': item['filename']} for item in items]

    return render_template('index.html', files=files)

import boto3
from boto3.dynamodb.conditions import Key

# ... other imports ...

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)  # Replace with your AWS region
# ... other routes and configurations ...

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    # If the user is already authenticated, redirect to the main page
    if current_user.is_authenticated:
        return redirect('/')

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        try:
            response = user_table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )

            if response.get('Items'):
                user_data = response['Items'][0]
                stored_password_hash = user_data.get('password_hash', None)

                if stored_password_hash and check_password_hash(stored_password_hash, password):
                    user = User(user_id=user_data['user_id'], username=user_data['username'], email=user_data['email'], password_hash=stored_password_hash, role_id=user_data['role_id'])
                    login_user(user)
                    flash('Logged In successfully!', 'success')
                    return redirect('/')
                else:
                    flash("Invalid email or password.", category='error')

        except ClientError as e:
                flash("Email is not registered. Please register first.", category='error')
                return redirect('/register')
        #else:
        #    flash("Email is not registered. Please register first.", category='error')
        #    return redirect('/register')

    return render_template('auth/login.html', form=form)



# logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect('/')

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')        



# ... other imports and app configuration ...

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if current_user.is_authenticated:
        return redirect('/')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)

        # Fetch the admin user's email from the environment variable
        admin_email = os.environ.get('ADMIN_USER')

        # Check if the email already exists in DynamoDB
        try:
            response = user_table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )

            if response.get('Items'):
                # Handle case where the email already exists
                flash('Email already registered!', 'error')
                return redirect('/login')
            else:
                # Determine the user's role based on their email
                if email == admin_email:
                    role = 'admin'
                else:
                    role = 'user'

                # Generate a unique user_id using secrets.token_hex()
                user_id = str(secrets.token_hex(16))
                print(user_id)
                # Create a new user record in DynamoDB
                user_data = {
                    'user_id': user_id,
                    'username': request.form.get('username'),
                    'email': email,
                    'password_hash': hashed_password,
                    'role': role  # Role can be 'user' or 'admin'
                }
                user_table.put_item(Item=user_data)

                flash('Account created successfully!', 'success')

                # Log in the newly registered user
                user = User(user_id=user_id, username=user_data['username'], email=email, password_hash=hashed_password, role=role)
                login_user(user)

                return redirect('/')
        except Exception as e:
            if email == admin_email:
                    role = 'admin'
            else:
                role = 'user'

            # Generate a unique user_id using secrets.token_hex()
            user_id = secrets.token_hex(16)

            # Create a new user record in DynamoDB
            user_data = {
                'user_id': user_id,
                'username': request.form.get('username'),
                'email': email,
                'password_hash': hashed_password,
                'role': role  # Role can be 'user' or 'admin'
            }
            user_table.put_item(Item=user_data)

            flash('Account created successfully!', 'success')

            # Log in the newly registered user
            user = User(user_id=user_id, username=user_data['username'], email=email, password_hash=hashed_password, role=role)
            login_user(user)

            return redirect('/')            

    return render_template('auth/register.html', form=form)

#... other routes and app configurations ...


def is_file_infected(file):
    try:
        cd = pyclamd.ClamdUnixSocket()
        scan_result = cd.scan_stream(file.read())
        file.seek(0)  # Reset the file stream position to the beginning
        if scan_result:
            virus_name = scan_result[file.filename]
            print(f'File {file.filename} is infected with {virus_name}')
            return True
        return False
    except pyclamd.ConnectionError:
        # Handle connection error to ClamAV daemon
        return False
    except Exception as e:
        # Handle other exceptions (e.g., invalid file, ClamAV not installed)
        print(f'Error scanning file: {str(e)}')
        return False



@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if current_user.role.name in ['admin', 'user']:
        if 'file' not in request.files:
            return "No file part"
        
        file = request.files['file']
        
        if file.filename == '':
            return "No selected file"
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            
            if is_file_infected(file):
                flash('File is infected with a virus', category='error')
                return redirect(request.url)
            
            # Generate a unique filename for storage in S3
            unique_filename = f"{current_user.id}_{filename}"
            
            # Upload the file to Amazon S3
            try:
                s3.upload_fileobj(
                    file,
                    'cyclic-tan-dark-goshawk-eu-west-1',  # Replace with your S3 bucket name
                    unique_filename
                )
            except Exception as e:
                print(f"Error uploading to S3: {str(e)}")
                flash("Error uploading file to Amazon S3.", category='error')
                return redirect(request.url)
            
            # Save file information to DynamoDB
            new_file = File(
                filename=filename,
                user_id=current_user.id,
                s3_object_key=unique_filename,  # Store the S3 object key
                file_size=os.path.getsize(file),  # Get file size from the uploaded file
                comment=request.form.get('comment')  # Get comment from the form
            )
            new_file.save_to_dynamodb()
            
            flash(f'{filename} Uploaded successfully!', 'success')
            
            return redirect('/')
        else:
            return "File type not allowed"
    else:
        return "Unauthorized"


# Your delete route here...
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    if current_user.role.name == 'admin':
        # the delete logic here
        file_to_delete = File.query.get(id)
        if file_to_delete:
            db.session.delete(file_to_delete)
            db.session.commit()
            flash(f'{file_to_delete.filename} has been deleted successfully!', 'success')
            return redirect('/')
        else:
            return "File not found."
    else:
        return "Unauthorized"

# Your download and preview routes here...

# download route
@app.route('/download/<int:id>')
@login_required
def download(id):
    file = File.query.get(id)
    file_data = io.BytesIO(file.data)
    file_data.seek(0)  # Reset the stream position to the beginning
    flash('Download Started successfully!', 'success')
    headers = {
        'Content-Disposition': f'attachment; filename={file.filename}'
    }

    return Response(
        file_data,
        headers=headers,
        content_type='application/octet-stream'
    )
    



@app.route('/password_reset_request', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordRequestForm()
    if current_user.is_authenticated:
        return redirect('/')
    
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            
            # Generate and send password reset link via email
            token = user.generate_password_reset_token()
            reset_url = f"{request.url_root}reset_password/{token}"
            user.password_reset_token = token

            
            subject = 'Password Reset Request'
            message = render_template('auth/reset_password_email.html', reset_url=reset_url)
            
            msg = Message(subject=subject, sender='musiitwaelijah@gmail.com', recipients=[email], body=message)
            mail.send(msg)
            
            flash('An email with instructions to reset your password has been sent to your email address.', 'success')
            return redirect(url_for('login'))
        flash('You are Not Registered!.', 'error')
        return redirect("/register")
    
    return render_template('auth/password_reset_request.html', form=form)



@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    print("SUCCESS!!!!")
    form = ResetPasswordForm()

    # Validate token and expiration time
    user = User.query.filter_by(password_reset_token=token).first()
    if user and not user.token_expired():
        print("User found with token:", user.password_reset_token)  # Debugging
        if request.method == 'POST':
            new_password = request.form.get('new_password')
            user.set_password(new_password)
            user.password_reset_token = None
            db.session.commit()
            flash("Password reset successful.", category="success")
            return redirect("/login")
        return render_template('auth/reset_password.html', token=token, form=form)
    
    return "Invalid or expired token."

# Handle 404 errors with the custom 404.html template
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500

@app.errorhandler(ConnectionError)
def handle_clamav_connection_error(error):
    # Log the error for debugging purposes
    logger.error("Error connecting to ClamAV daemon: %s", error)

    # You can customize the error message to display to the user
    error_message = "Error connecting to the virus scanner. Please try again later."
    
    # Render an error template or redirect with the error message
    return render_template('error.html', error_message=error_message), 500

#if __name__ == "__main__":
#    with app.app_context():
 #       app.run()


if __name__ == '__main__':
    with app.app_context():
        create_dynamodb_index()
        sys.argv = "gunicorn --bind 0.0.0.0:5151 app:app".split()
        sys.exit(run())
