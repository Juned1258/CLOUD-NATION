from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import boto3
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Logging to CloudWatch (add watchtower later)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        try:
            user = User(username=username, password=password)
            db.session.add(user)
            db.session.commit()
            logger.info(f"User {username} created")

            # SES Email
            ses = boto3.client('ses', region_name='us-east-1')
            ses.send_email(
                Source='noreply@cloud-nation.com',
                Destination={'ToAddresses': [f"{username}@example.com"]},  # Replace with real email
                Message={'Subject': {'Data': 'Welcome to Cloud Nation!'}, 'Body': {'Text': {'Data': 'Account created! Start your DevOps journey.'}}}
            )

            # SNS SMS
            sns = boto3.client('sns')
            sns.publish(TopicArn=os.environ.get('SNS_TOPIC_ARN'), Message=f'Welcome, {username}! Batch 101 starts Aug 1, 2025.')

            flash('Account created! Check your email/SMS.')
        except Exception as e:
            flash('Error creating account.')
            logger.error(f"Signup error: {e}")
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
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    # Fetch attendance from DB (extend User model for real data)
    return render_template('dashboard.html', user=user.username)  # Pass dynamic data

@app.route('/thankyou')  # For static mode fallback
def thankyou():
    return '<h1>Account created! (Demo)</h1>'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)