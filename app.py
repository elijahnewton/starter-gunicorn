import subprocess
import sys

subprocess.check_call([sys.executable, "-m", "pip", "install", "-r requirements.txt"])

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
import os
from flask_sqlalchemy import SQLAlchemy

basedir = os.path.abspath(os.path.dirname(__file__))
secret_key = secrets.token_hex(16)

SECRET_KEY = os.getenv('SECRET_KEY')
app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///' + os.path.join(basedir, 'stored_files.db')
app.config['UPLOAD_FOLDER'] = 'uploads'
db = SQLAlchemy(app)
migrate = Migrate(app, db) 
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__) 

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

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))
    
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    description = db.Column(db.String(200))
    users = db.relationship('User', backref='role')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    password_reset_token = db.Column(db.String(120))
    password_reset_expiration = db.Column(db.DateTime)

    def __init__(self, user_name, email, password,role_id):
        self.user_name = user_name
        self.email = email
        self.password_hash = generate_password_hash(password)
        self.role_id = role_id  # Initialize with no role

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_password_reset_token(self):
        token = secrets.token_urlsafe(32)  # Generate a random URL-safe token (you can adjust the length)
        self.password_reset_token = token
        self.password_reset_expiration = datetime.utcnow() + timedelta(hours=1)  # Set token expiration time (e.g., 1 hour)
        db.session.commit()
        return token

    def token_expired(self):
        
        if self.password_reset_expiration is None:
            return True  # Token expiration is not set
        current_time = datetime.utcnow()
        return current_time > self.password_reset_expiration

    
    
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# default routes
@app.route('/', methods=["GET", "POST"])
def index():
    files = File.query.all()
    return render_template('index.html', files=files)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    # If the user is already authenticated, redirect to the main page
    if current_user.is_authenticated:
        return redirect('/')

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user:
            print(f"Entered Password: {password}")
            print(f"Stored Hashed Password: {user.password_hash}")
            if user.check_password(password):
                print("Passwords Match")
                login_user(user)
                flash('Logged In successfully!', 'success')
                return redirect('/')
            else:
                print("Passwords Do Not Match")
                flash("Invalid email or password.", category='error')
        else:
            print("User Not Found")
            flash("Email is not registered. Please register first.", category='error')
            return redirect('/register')

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

# register route
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
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            # Handle case where the email already exists
            flash('Email already registered!', 'error')
            redirect('/login')
        else:

            if request.form.get('email')== admin_email:
                role = Role.query.filter_by(name='admin').first()

            else:
                role = Role.query.filter_by(name='user').first()

            try:
                new_user = User(user_name=request.form.get('username'), email=request.form.get('email'), password=password, role_id=role.id)
                db.session.add(new_user)
                db.session.commit()# Role can be 'user' or 'admin'
                deleted = User.query.filter_by(name='deleted').first()
                if deleted is None:
                    deleted = User(user_name=request.form.get('username'), email=request.form.get('email'), password=password, role_id=role.id)
                    db.session.add(deleted)
                    db.session.commit()
            except:
                admin_role = Role.query.filter_by(name='admin').first()
                if admin_role is None:
                    admin_role = Role(name='admin', description='Administrator Role')
                    db.session.add(admin_role)
                user_role = Role.query.filter_by(name='user').first()

                if user_role is None:
                    user_role = Role(name='user', description='Regular User Role')
                    db.session.add(user_role)

                if request.form.get('email')== admin_email:
                    role = Role.query.filter_by(name='admin').first()

                else:
                    role = Role.query.filter_by(name='user').first()
                new_user = User(user_name=request.form.get('username'), email=request.form.get('email'), password=password, role_id=role.id)
                db.session.add(new_user)
                db.session.commit()# Role can be 'user' or 'admin'

                # Check if "user" role exists
                user_role = Role.query.filter_by(name='user').first()
                if user_role is None:
                    user_role = Role(name='user', description='Regular User Role')
                    db.session.add(user_role)

        
            flash('Account created successfully!', 'success')
        
            login_user(new_user)
            return redirect('/')

    return render_template('auth/register.html', form = form)

def is_file_infected(file_path):
        try:
            cd = pyclamd.ClamdUnixSocket()
            scan_result = cd.scan_file(file_path)
            if scan_result:
                return True
            return False
        except pyclamd.ConnectionError:
            # Handle connection error to ClamAV daemon
            return False


@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if current_user.role.name in ['admin', 'user']:
        if 'file' not in request.files:
            print(request.files)
            return "No file part"
        
        file = request.files['file']
        
        if file.filename == '':
            return "No selected file"
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_data = file.read()  # Read the binary data of the file
            
            if is_file_infected(file_data):
                flash('File is infected with a virus', category='error')
                return redirect(request.url)
            
            new_file = File(filename=filename, data=file_data, user_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()
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

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run()
