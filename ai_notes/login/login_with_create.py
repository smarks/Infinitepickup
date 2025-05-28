#!/usr/bin/env python3
"""
AWS Cognito Flask Login Application

A complete web application that demonstrates user authentication using AWS Cognito.
Includes user registration, email verification, login, logout, and protected routes.

Features:
- User registration with email verification
- Secure login/logout functionality
- Protected routes with automatic token refresh
- Session management with proper security
- Password strength requirements
- Resend verification codes
- Comprehensive error handling

Requirements:
- pip install flask boto3 python-jose[cryptography]
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)
- AWS Cognito User Pool and App Client configured with email verification enabled
"""

import os
import json
import base64
from datetime import datetime, timedelta
from functools import wraps

import boto3
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, jsonify
from botocore.exceptions import ClientError
import hmac
import hashlib


class CognitoAuth:
    """AWS Cognito authentication handler"""

    def __init__(self, user_pool_id, client_id, client_secret, region='us-east-1'):
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.region = region
        self.client = boto3.client('cognito-idp', region_name=region)

    def _calculate_secret_hash(self, username):
        """Calculate the secret hash for Cognito authentication"""
        message = username + self.client_id
        key = self.client_secret.encode('utf-8')
        return base64.b64encode(
            hmac.new(key, message.encode('utf-8'), digestmod=hashlib.sha256).digest()
        ).decode()

    def authenticate_user(self, username, password):
        """Authenticate user with AWS Cognito"""
        try:
            secret_hash = self._calculate_secret_hash(username)

            response = self.client.admin_initiate_auth(
                UserPoolId=self.user_pool_id,
                ClientId=self.client_id,
                AuthFlow='ADMIN_NO_SRP_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password,
                    'SECRET_HASH': secret_hash
                }
            )

            return {
                'success': True,
                'tokens': response['AuthenticationResult'],
                'username': username
            }

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NotAuthorizedException':
                return {'success': False, 'error': 'Invalid username or password'}
            elif error_code == 'UserNotConfirmedException':
                return {'success': False, 'error': 'User account not confirmed'}
            elif error_code == 'PasswordResetRequiredException':
                return {'success': False, 'error': 'Password reset required'}
            else:
                return {'success': False, 'error': f'Authentication failed: {str(e)}'}

    def get_user_info(self, access_token):
        """Get user information from access token"""
        try:
            response = self.client.get_user(AccessToken=access_token)
            user_attributes = {attr['Name']: attr['Value'] for attr in response['UserAttributes']}
            return {
                'success': True,
                'username': response['Username'],
                'attributes': user_attributes
            }
        except ClientError as e:
            return {'success': False, 'error': str(e)}

    def refresh_token(self, refresh_token, username):
        """Refresh access token using refresh token"""
        try:
            secret_hash = self._calculate_secret_hash(username)

            response = self.client.admin_initiate_auth(
                UserPoolId=self.user_pool_id,
                ClientId=self.client_id,
                AuthFlow='REFRESH_TOKEN_AUTH',
                AuthParameters={
                    'REFRESH_TOKEN': refresh_token,
                    'SECRET_HASH': secret_hash
                }
            )

            return {
                'success': True,
                'tokens': response['AuthenticationResult']
            }
        except ClientError as e:
            return {'success': False, 'error': str(e)}

    def sign_up_user(self, username, password, email, first_name=None, last_name=None):
        """Sign up a new user with AWS Cognito"""
        try:
            secret_hash = self._calculate_secret_hash(username)

            user_attributes = [
                {'Name': 'email', 'Value': email}
            ]

            if first_name:
                user_attributes.append({'Name': 'given_name', 'Value': first_name})
            if last_name:
                user_attributes.append({'Name': 'family_name', 'Value': last_name})

            response = self.client.sign_up(
                ClientId=self.client_id,
                Username=username,
                Password=password,
                SecretHash=secret_hash,
                UserAttributes=user_attributes
            )

            return {
                'success': True,
                'user_sub': response['UserSub'],
                'confirmation_required': not response['UserConfirmed']
            }

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'UsernameExistsException':
                return {'success': False, 'error': 'Username already exists'}
            elif error_code == 'InvalidPasswordException':
                return {'success': False, 'error': 'Password does not meet requirements'}
            elif error_code == 'InvalidParameterException':
                return {'success': False, 'error': 'Invalid email format or missing required fields'}
            else:
                return {'success': False, 'error': f'Registration failed: {str(e)}'}

    def confirm_sign_up(self, username, confirmation_code):
        """Confirm user sign-up with verification code"""
        try:
            secret_hash = self._calculate_secret_hash(username)

            response = self.client.confirm_sign_up(
                ClientId=self.client_id,
                Username=username,
                ConfirmationCode=confirmation_code,
                SecretHash=secret_hash
            )

            return {'success': True}

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'CodeMismatchException':
                return {'success': False, 'error': 'Invalid verification code'}
            elif error_code == 'ExpiredCodeException':
                return {'success': False, 'error': 'Verification code has expired'}
            elif error_code == 'NotAuthorizedException':
                return {'success': False, 'error': 'User is already confirmed or code is invalid'}
            else:
                return {'success': False, 'error': f'Confirmation failed: {str(e)}'}

    def resend_confirmation_code(self, username):
        """Resend confirmation code to user"""
        try:
            secret_hash = self._calculate_secret_hash(username)

            response = self.client.resend_confirmation_code(
                ClientId=self.client_id,
                Username=username,
                SecretHash=secret_hash
            )

            return {'success': True}

        except ClientError as e:
            return {'success': False, 'error': f'Failed to resend code: {str(e)}'}


# Flask Application Configuration
app = Flask(__name__)

# Configuration - Replace with your actual values
app.config.update({
    'SECRET_KEY': os.environ.get('SECRET_KEY', 'your-secret-key-here'),
    'COGNITO_USER_POOL_ID': os.environ.get('COGNITO_USER_POOL_ID', 'us-east-1_xxxxxxxxx'),
    'COGNITO_CLIENT_ID': os.environ.get('COGNITO_CLIENT_ID', 'your-client-id'),
    'COGNITO_CLIENT_SECRET': os.environ.get('COGNITO_CLIENT_SECRET', 'your-client-secret'),
    'COGNITO_REGION': os.environ.get('COGNITO_REGION', 'us-east-1'),
    'PERMANENT_SESSION_LIFETIME': timedelta(hours=1)
})

# Initialize Cognito Auth
cognito_auth = CognitoAuth(
    user_pool_id=app.config['COGNITO_USER_POOL_ID'],
    client_id=app.config['COGNITO_CLIENT_ID'],
    client_secret=app.config['COGNITO_CLIENT_SECRET'],
    region=app.config['COGNITO_REGION']
)


def login_required(f):
    """Decorator to require login for protected routes"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))

        # Check if access token is expired and refresh if needed
        if 'token_expires' in session and datetime.now() > session['token_expires']:
            if 'refresh_token' in session:
                result = cognito_auth.refresh_token(
                    session['refresh_token'],
                    session['user']['username']
                )
                if result['success']:
                    tokens = result['tokens']
                    session['access_token'] = tokens['AccessToken']
                    session['token_expires'] = datetime.now() + timedelta(seconds=tokens['ExpiresIn'])
                    if 'RefreshToken' in tokens:
                        session['refresh_token'] = tokens['RefreshToken']
                else:
                    session.clear()
                    flash('Session expired. Please log in again.', 'warning')
                    return redirect(url_for('login'))
            else:
                session.clear()
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('login'))

        return f(*args, **kwargs)

    return decorated_function


# HTML Templates
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Cognito Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 400px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .login-container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 10px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
        }
        button:hover {
            background-color: #0056b3;
        }
        .alert {
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 4px;
        }
        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .alert-warning {
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>AWS Cognito Login</h1>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>

            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>

            <button type="submit">Login</button>
        </form>

        <div style="text-align: center; margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee;">
            <p>Don't have an account? <a href="{{ url_for('register') }}" style="color: #007bff;">Sign up here</a></p>
        </div>
    </div>
</body>
</html>
"""

REGISTER_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up - AWS Cognito</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 450px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .register-container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], input[type="email"], input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 10px;
            background-color: #28a745;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
            margin-bottom: 10px;
        }
        button:hover {
            background-color: #218838;
        }
        .alert {
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 4px;
        }
        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .alert-warning {
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        .password-requirements {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 15px;
            font-size: 14px;
        }
        .password-requirements h4 {
            margin-top: 0;
            color: #495057;
        }
        .password-requirements ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        .login-link {
            text-align: center;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
    </style>
</head>
<body>
    <div class="register-container">
        <h1>Create Account</h1>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <div class="password-requirements">
            <h4>Password Requirements:</h4>
            <ul>
                <li>At least 8 characters long</li>
                <li>Contains uppercase and lowercase letters</li>
                <li>Contains at least one number</li>
                <li>Contains at least one special character</li>
            </ul>
        </div>

        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required 
                       value="{{ request.form.username if request.form.username else '' }}">
            </div>

            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required 
                       value="{{ request.form.email if request.form.email else '' }}">
            </div>

            <div class="form-group">
                <label for="first_name">First Name (Optional):</label>
                <input type="text" id="first_name" name="first_name" 
                       value="{{ request.form.first_name if request.form.first_name else '' }}">
            </div>

            <div class="form-group">
                <label for="last_name">Last Name (Optional):</label>
                <input type="text" id="last_name" name="last_name" 
                       value="{{ request.form.last_name if request.form.last_name else '' }}">
            </div>

            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>

            <div class="form-group">
                <label for="confirm_password">Confirm Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>

            <button type="submit">Create Account</button>
        </form>

        <div class="login-link">
            <p>Already have an account? <a href="{{ url_for('login') }}" style="color: #007bff;">Login here</a></p>
        </div>
    </div>
</body>
</html>
"""

CONFIRM_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confirm Account - AWS Cognito</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 450px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .confirm-container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 10px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
            margin-bottom: 10px;
        }
        button:hover {
            background-color: #0056b3;
        }
        .resend-btn {
            background-color: #6c757d;
            font-size: 14px;
            padding: 8px;
        }
        .resend-btn:hover {
            background-color: #545b62;
        }
        .alert {
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 4px;
        }
        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .alert-info {
            background-color: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        .instructions {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="confirm-container">
        <h1>Confirm Your Account</h1>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <div class="instructions">
            <p><strong>Check your email!</strong></p>
            <p>We've sent a verification code to your email address. Enter the code below to complete your registration.</p>
            <p><strong>Username:</strong> {{ username }}</p>
        </div>

        <form method="POST">
            <input type="hidden" name="username" value="{{ username }}">

            <div class="form-group">
                <label for="confirmation_code">Verification Code:</label>
                <input type="text" id="confirmation_code" name="confirmation_code" 
                       required placeholder="Enter 6-digit code" maxlength="6">
            </div>

            <button type="submit">Confirm Account</button>
        </form>

        <form method="POST" action="{{ url_for('resend_confirmation') }}">
            <input type="hidden" name="username" value="{{ username }}">
            <button type="submit" class="resend-btn">Resend Verification Code</button>
        </form>

        <div style="text-align: center; margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee;">
            <p><a href="{{ url_for('login') }}" style="color: #007bff;">Back to Login</a></p>
        </div>
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - AWS Cognito App</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 20px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .dashboard-container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }
        .user-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            margin-bottom: 20px;
        }
        .user-info h3 {
            margin-top: 0;
            color: #333;
        }
        .user-detail {
            margin: 10px 0;
        }
        .user-detail strong {
            display: inline-block;
            width: 120px;
        }
        .logout-btn {
            background-color: #dc3545;
            color: white;
            padding: 8px 16px;
            text-decoration: none;
            border-radius: 4px;
            border: none;
            cursor: pointer;
        }
        .logout-btn:hover {
            background-color: #c82333;
        }
        .alert {
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 4px;
        }
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        h1 {
            color: #333;
            margin: 0;
        }
        .status {
            color: #28a745;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="header">
            <h1>Dashboard</h1>
            <a href="{{ url_for('logout') }}" class="logout-btn">Logout</a>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <div class="user-info">
            <h3>Welcome, {{ user.username }}!</h3>
            <div class="user-detail">
                <strong>Status:</strong> <span class="status">Successfully authenticated via AWS Cognito</span>
            </div>
            <div class="user-detail">
                <strong>Username:</strong> {{ user.username }}
            </div>
            {% if user.attributes %}
                {% for key, value in user.attributes.items() %}
                    <div class="user-detail">
                        <strong>{{ key.replace('_', ' ').title() }}:</strong> {{ value }}
                    </div>
                {% endfor %}
            {% endif %}
            <div class="user-detail">
                <strong>Session Started:</strong> {{ session_start }}
            </div>
        </div>

        <p>This is a protected area that requires AWS Cognito authentication. 
        You can now access any protected routes in the application.</p>

        <h3>Available Actions:</h3>
        <ul>
            <li><a href="{{ url_for('profile') }}">View Profile</a></li>
            <li><a href="{{ url_for('protected_api') }}">Protected API Endpoint</a></li>
            <li><a href="{{ url_for('logout') }}">Logout</a></li>
        </ul>

        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 14px; color: #666;">
            <p><strong>Note:</strong> This application demonstrates AWS Cognito integration with user registration, 
            email verification, secure login, and session management.</p>
        </div>
    </div>
</body>
</html>
"""


# Routes
@app.route('/')
def index():
    """Home page - redirect to dashboard if logged in, otherwise to login"""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication handler"""
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template_string(LOGIN_TEMPLATE)

        # Authenticate with AWS Cognito
        result = cognito_auth.authenticate_user(username, password)

        if result['success']:
            tokens = result['tokens']

            # Get user information
            user_info = cognito_auth.get_user_info(tokens['AccessToken'])

            if user_info['success']:
                # Store user session
                session.permanent = True
                session['user'] = {
                    'username': user_info['username'],
                    'attributes': user_info['attributes']
                }
                session['access_token'] = tokens['AccessToken']
                session['refresh_token'] = tokens.get('RefreshToken')
                session['token_expires'] = datetime.now() + timedelta(seconds=tokens['ExpiresIn'])
                session['login_time'] = datetime.now().isoformat()

                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Failed to retrieve user information.', 'error')
        else:
            flash(result['error'], 'error')

    return render_template_string(LOGIN_TEMPLATE)


@app.route('/dashboard')
@login_required
def dashboard():
    """Protected dashboard page"""
    session_start = datetime.fromisoformat(session['login_time']).strftime('%Y-%m-%d %H:%M:%S')
    return render_template_string(
        DASHBOARD_TEMPLATE,
        user=session['user'],
        session_start=session_start
    )


@app.route('/profile')
@login_required
def profile():
    """Protected profile page"""
    user_info = cognito_auth.get_user_info(session['access_token'])

    if user_info['success']:
        # Update session with latest user info
        session['user']['attributes'] = user_info['attributes']
        return jsonify({
            'username': user_info['username'],
            'attributes': user_info['attributes'],
            'session_info': {
                'login_time': session['login_time'],
                'token_expires': session['token_expires'].isoformat()
            }
        })
    else:
        return jsonify({'error': 'Failed to retrieve user information'}), 500


@app.route('/api/protected')
@login_required
def protected_api():
    """Protected API endpoint example"""
    return jsonify({
        'message': 'This is a protected API endpoint',
        'user': session['user']['username'],
        'timestamp': datetime.now().isoformat(),
        'authenticated_via': 'AWS Cognito'
    })


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page and handler"""
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()

        # Validation
        if not username or not email or not password:
            flash('Please fill in all required fields.', 'error')
            return render_template_string(REGISTER_TEMPLATE)

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template_string(REGISTER_TEMPLATE)

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template_string(REGISTER_TEMPLATE)

        # Register user with AWS Cognito
        result = cognito_auth.sign_up_user(
            username=username,
            password=password,
            email=email,
            first_name=first_name if first_name else None,
            last_name=last_name if last_name else None
        )

        if result['success']:
            if result['confirmation_required']:
                flash('Registration successful! Please check your email for a verification code.', 'success')
                return redirect(url_for('confirm_account', username=username))
            else:
                flash('Registration successful! You can now log in.', 'success')
                return redirect(url_for('login'))
        else:
            flash(result['error'], 'error')

    return render_template_string(REGISTER_TEMPLATE)


@app.route('/confirm/<username>', methods=['GET', 'POST'])
def confirm_account(username):
    """Account confirmation page and handler"""
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        confirmation_code = request.form['confirmation_code'].strip()
        username = request.form['username']

        if not confirmation_code:
            flash('Please enter the verification code.', 'error')
            return render_template_string(CONFIRM_TEMPLATE, username=username)

        # Confirm user registration
        result = cognito_auth.confirm_sign_up(username, confirmation_code)

        if result['success']:
            flash('Account confirmed successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash(result['error'], 'error')

    return render_template_string(CONFIRM_TEMPLATE, username=username)


@app.route('/resend-confirmation', methods=['POST'])
def resend_confirmation():
    """Resend confirmation code"""
    username = request.form['username']

    result = cognito_auth.resend_confirmation_code(username)

    if result['success']:
        flash('Verification code sent! Please check your email.', 'info')
    else:
        flash(result['error'], 'error')

    return redirect(url_for('confirm_account', username=username))


@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))


@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Configuration check
    required_config = [
        'COGNITO_USER_POOL_ID',
        'COGNITO_CLIENT_ID',
        'COGNITO_CLIENT_SECRET'
    ]

    missing_config = [key for key in required_config if not app.config.get(key) or app.config[key].startswith('your-')]

    if missing_config:
        print("ERROR: Missing required configuration:")
        for key in missing_config:
            print(f"  - {key}")
        print("\nPlease set these environment variables or update the configuration in the code.")
        print("\nExample:")
        print("export COGNITO_USER_POOL_ID='us-east-1_xxxxxxxxx'")
        print("export COGNITO_CLIENT_ID='your-app-client-id'")
        print("export COGNITO_CLIENT_SECRET='your-app-client-secret'")
        exit(1)

    print("Starting AWS Cognito Flask Application...")
    print(f"User Pool ID: {app.config['COGNITO_USER_POOL_ID']}")
    print(f"Client ID: {app.config['COGNITO_CLIENT_ID']}")
    print(f"Region: {app.config['COGNITO_REGION']}")
    print("\nFeatures:")
    print("- User Registration with Email Verification")
    print("- Secure Login/Logout")
    print("- Protected Routes with Token Refresh")
    print("- Session Management")
    print("\nApplication will be available at: http://localhost:5000")

    app.run(debug=True, host='0.0.0.0', port=5000)