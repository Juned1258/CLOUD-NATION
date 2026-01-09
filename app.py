from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import boto3
import logging
import watchtower # NEW: For CloudWatch integration

# --- 1. Database Configuration (Production vs. Development) ---

# Get individual DB components from OS environment variables set on EC2/in Gunicorn .env
DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASS = os.environ.get('DB_PASS')
DB_NAME = os.environ.get('DB_NAME')
DB_PORT = os.environ.get('DB_PORT', '5432')

# Define the production URI using the environment variables
# IMPORTANT: Change the driver if you are using MySQL (e.g., 'mysql+pymysql')
if DB_HOST:
    # Production DB URI (Example uses PostgreSQL)
    DB_URI = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
else:
    # Fallback for local testing (not used in Gunicorn/EC2 deployment)
    DB_URI = 'sqlite:///users.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = True # Keep True for dev/sqlite for simplicity

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = SQLALCHEMY_TRACK_MODIFICATIONS

db = SQLAlchemy(app)

# --- 2. Centralized CloudWatch Logging Setup ---

LOG_GROUP_NAME = os.environ.get('CLOUDWATCH_LOG_GROUP', 'CloudNationAppLogs')
LOG_STREAM_NAME = os.environ.get('CLOUDWATCH_LOG_STREAM', 'production-stream')

# Clear default handlers to prevent duplicate logging
logging.getLogger().handlers = []
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add Watchtower handler to send logs to CloudWatch
try:
    cw_handler = watchtower.CloudWatchLogHandler(
        log_group_name=LOG_GROUP_NAME,
        stream_name=LOG_STREAM_NAME,
        boto3_client=boto3.client('logs', region_name='us-east-1') # Optional, uses default region
    )
    logger.addHandler(cw_handler)
    logger.info("Watchtower CloudWatch logging configured.")
except Exception as e:
    logger.error(f"Failed to configure Watchtower. Ensure IAM role permissions are set. Error: {e}")

# --- 3. Database Model and Routes ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

#----------------------------------------------------------------------#
# --- 3. Database Model and Routes (CONTINUED) ---

# NEW: Root Route
@app.route('/')
def home():
    # Since this is a login-required app, it's common practice to redirect the root
    # to the login page, or if a user is logged in, to the dashboard.
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login')) # Redirect user to the login page
#------------------------------------------------------------------------#

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            logger.warning(f"Signup attempt with existing username: {username}")
            return redirect(url_for('signup'))

        try:
            user = User(username=username, password=password)
            db.session.add(user)
            db.session.commit()
            logger.info(f"User {username} created successfully.")

            # --- Boto3 Calls (Requires IAM Role Permissions) ---

            # SES Email
            ses = boto3.client('ses', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
            ses.send_email(
                Source=os.environ.get('SES_SOURCE_EMAIL', 'noreply@cloud-nation.com'),
                Destination={'ToAddresses': [f"{username}@example.com"]},
                Message={'Subject': {'Data': 'Welcome to Cloud Nation!'}, 'Body': {'Text': {'Data': 'Account created! Start your DevOps journey.'}}}
            )
            logger.info(f"SES email triggered for user {username}.")

            # SNS SMS
            sns = boto3.client('sns', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
            sns.publish(
                TopicArn=os.environ.get('SNS_TOPIC_ARN'),
                Message=f'Welcome, {username}! Batch 101 starts Aug 1, 2025.'
            )
            logger.info(f"SNS SMS triggered for user {username}.")

            flash('Account created! Check your email/SMS.')
        except Exception as e:
            db.session.rollback() # Rollback transaction on failure
            flash('Error creating account. Check server logs.')
            logger.error(f"Signup error for user {username}: {e}")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['loginId']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            logger.info(f"Login success: {user.username}")
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
        logger.warning(f"Failed login attempt for ID: {request.form['loginId']}")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user.username)

@app.route('/thankyou')
def thankyou():
    return '<h1>Account created! (Demo)</h1>'

if __name__ == '__main__':
    # Creates the database schema if running locally (sqlite) or the table if connecting to RDS
    with app.app_context():
        db.create_all()
    # Note: The EC2 deployment runs this via Gunicorn, not this app.run() block.
    app.run(debug=True, host='0.0.0.0', port=5000)
