#!/usr/bin/env python3
"""
Comprehensive test suite for AWS Cognito Flask Login Application

This test suite covers:
- Unit tests for CognitoAuth class
- Integration tests for Flask routes
- Authentication flow testing
- Error handling scenarios
- Session management
- Form validation

Requirements for testing:
pip install pytest pytest-mock pytest-flask moto[cognitoidp]

Run tests with:
pytest test_app.py -v
pytest test_app.py::TestCognitoAuth -v  # Run specific test class
pytest test_app.py -k "test_login" -v   # Run tests matching pattern
"""

import pytest
import json
import hmac
import hashlib
import base64
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

import boto3
from moto import mock_cognitoidp
from botocore.exceptions import ClientError


# Import the application (assuming it's in app.py)
# In real scenario, you'd import from your main module
# from app import app, cognito_auth, CognitoAuth

# For testing purposes, we'll define a minimal version here
# In practice, you'd import these from your main application file
class CognitoAuth:
    """AWS Cognito authentication handler - Test Version"""

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


# Test Configuration
TEST_CONFIG = {
    'TESTING': True,
    'SECRET_KEY': 'test-secret-key',
    'COGNITO_USER_POOL_ID': 'us-east-1_test123456',
    'COGNITO_CLIENT_ID': 'test-client-id',
    'COGNITO_CLIENT_SECRET': 'test-client-secret',
    'COGNITO_REGION': 'us-east-1',
    'WTF_CSRF_ENABLED': False  # Disable CSRF for testing
}


class TestCognitoAuth:
    """Unit tests for CognitoAuth class"""

    @pytest.fixture
    def cognito_auth(self):
        """Create CognitoAuth instance for testing"""
        return CognitoAuth(
            user_pool_id=TEST_CONFIG['COGNITO_USER_POOL_ID'],
            client_id=TEST_CONFIG['COGNITO_CLIENT_ID'],
            client_secret=TEST_CONFIG['COGNITO_CLIENT_SECRET'],
            region=TEST_CONFIG['COGNITO_REGION']
        )

    def test_calculate_secret_hash(self, cognito_auth):
        """Test secret hash calculation"""
        username = "testuser"
        secret_hash = cognito_auth._calculate_secret_hash(username)

        # Verify it's a base64 encoded string
        assert isinstance(secret_hash, str)
        assert len(secret_hash) > 0

        # Should be consistent
        assert secret_hash == cognito_auth._calculate_secret_hash(username)

    @patch('boto3.client')
    def test_authenticate_user_success(self, mock_boto_client, cognito_auth):
        """Test successful user authentication"""
        # Mock successful response
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        cognito_auth.client = mock_client

        mock_client.admin_initiate_auth.return_value = {
            'AuthenticationResult': {
                'AccessToken': 'test-access-token',
                'RefreshToken': 'test-refresh-token',
                'ExpiresIn': 3600
            }
        }

        result = cognito_auth.authenticate_user('testuser', 'password123')

        assert result['success'] is True
        assert result['username'] == 'testuser'
        assert 'tokens' in result
        assert result['tokens']['AccessToken'] == 'test-access-token'

    @patch('boto3.client')
    def test_authenticate_user_invalid_credentials(self, mock_boto_client, cognito_auth):
        """Test authentication with invalid credentials"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        cognito_auth.client = mock_client

        # Mock ClientError for invalid credentials
        error_response = {
            'Error': {
                'Code': 'NotAuthorizedException',
                'Message': 'Incorrect username or password.'
            }
        }
        mock_client.admin_initiate_auth.side_effect = ClientError(error_response, 'AdminInitiateAuth')

        result = cognito_auth.authenticate_user('testuser', 'wrongpassword')

        assert result['success'] is False
        assert result['error'] == 'Invalid username or password'

    @patch('boto3.client')
    def test_authenticate_user_unconfirmed(self, mock_boto_client, cognito_auth):
        """Test authentication with unconfirmed user"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        cognito_auth.client = mock_client

        error_response = {
            'Error': {
                'Code': 'UserNotConfirmedException',
                'Message': 'User is not confirmed.'
            }
        }
        mock_client.admin_initiate_auth.side_effect = ClientError(error_response, 'AdminInitiateAuth')

        result = cognito_auth.authenticate_user('testuser', 'password123')

        assert result['success'] is False
        assert result['error'] == 'User account not confirmed'

    @patch('boto3.client')
    def test_sign_up_user_success(self, mock_boto_client, cognito_auth):
        """Test successful user registration"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        cognito_auth.client = mock_client

        mock_client.sign_up.return_value = {
            'UserSub': 'test-user-sub-id',
            'UserConfirmed': False
        }

        result = cognito_auth.sign_up_user(
            username='newuser',
            password='Password123!',
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )

        assert result['success'] is True
        assert result['user_sub'] == 'test-user-sub-id'
        assert result['confirmation_required'] is True

        # Verify correct parameters were passed
        mock_client.sign_up.assert_called_once()
        call_args = mock_client.sign_up.call_args[1]
        assert call_args['Username'] == 'newuser'
        assert call_args['Password'] == 'Password123!'
        assert any(attr['Name'] == 'email' and attr['Value'] == 'test@example.com'
                   for attr in call_args['UserAttributes'])

    @patch('boto3.client')
    def test_sign_up_user_duplicate_username(self, mock_boto_client, cognito_auth):
        """Test registration with existing username"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        cognito_auth.client = mock_client

        error_response = {
            'Error': {
                'Code': 'UsernameExistsException',
                'Message': 'An account with the given username already exists.'
            }
        }
        mock_client.sign_up.side_effect = ClientError(error_response, 'SignUp')

        result = cognito_auth.sign_up_user('existinguser', 'Password123!', 'test@example.com')

        assert result['success'] is False
        assert result['error'] == 'Username already exists'

    @patch('boto3.client')
    def test_confirm_sign_up_success(self, mock_boto_client, cognito_auth):
        """Test successful account confirmation"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        cognito_auth.client = mock_client

        mock_client.confirm_sign_up.return_value = {}

        result = cognito_auth.confirm_sign_up('testuser', '123456')

        assert result['success'] is True

    @patch('boto3.client')
    def test_confirm_sign_up_invalid_code(self, mock_boto_client, cognito_auth):
        """Test confirmation with invalid code"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        cognito_auth.client = mock_client

        error_response = {
            'Error': {
                'Code': 'CodeMismatchException',
                'Message': 'Invalid verification code provided.'
            }
        }
        mock_client.confirm_sign_up.side_effect = ClientError(error_response, 'ConfirmSignUp')

        result = cognito_auth.confirm_sign_up('testuser', '000000')

        assert result['success'] is False
        assert result['error'] == 'Invalid verification code'

    @patch('boto3.client')
    def test_get_user_info_success(self, mock_boto_client, cognito_auth):
        """Test successful user info retrieval"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        cognito_auth.client = mock_client

        mock_client.get_user.return_value = {
            'Username': 'testuser',
            'UserAttributes': [
                {'Name': 'email', 'Value': 'test@example.com'},
                {'Name': 'given_name', 'Value': 'Test'},
                {'Name': 'family_name', 'Value': 'User'}
            ]
        }

        result = cognito_auth.get_user_info('test-access-token')

        assert result['success'] is True
        assert result['username'] == 'testuser'
        assert result['attributes']['email'] == 'test@example.com'
        assert result['attributes']['given_name'] == 'Test'


class TestFlaskRoutes:
    """Integration tests for Flask routes"""

    @pytest.fixture
    def app(self):
        """Create Flask app for testing"""
        from flask import Flask
        app = Flask(__name__)
        app.config.update(TEST_CONFIG)
        return app

    @pytest.fixture
    def client(self, app):
        """Create test client"""
        return app.test_client()

    @pytest.fixture
    def mock_cognito_auth(self):
        """Mock CognitoAuth for testing"""
        with patch('app.cognito_auth') as mock_auth:
            yield mock_auth

    def test_index_redirect_to_login(self, client):
        """Test index page redirects to login when not authenticated"""
        response = client.get('/')
        assert response.status_code == 302
        assert '/login' in response.location

    def test_login_page_get(self, client):
        """Test login page loads correctly"""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'AWS Cognito Login' in response.data
        assert b'Username:' in response.data
        assert b'Password:' in response.data

    @patch('app.cognito_auth')
    def test_login_post_success(self, mock_cognito_auth, client):
        """Test successful login"""
        # Mock successful authentication
        mock_cognito_auth.authenticate_user.return_value = {
            'success': True,
            'tokens': {
                'AccessToken': 'test-access-token',
                'RefreshToken': 'test-refresh-token',
                'ExpiresIn': 3600
            },
            'username': 'testuser'
        }

        mock_cognito_auth.get_user_info.return_value = {
            'success': True,
            'username': 'testuser',
            'attributes': {'email': 'test@example.com'}
        }

        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'password123'
        })

        assert response.status_code == 302
        assert '/dashboard' in response.location

    @patch('app.cognito_auth')
    def test_login_post_invalid_credentials(self, mock_cognito_auth, client):
        """Test login with invalid credentials"""
        mock_cognito_auth.authenticate_user.return_value = {
            'success': False,
            'error': 'Invalid username or password'
        }

        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'wrongpassword'
        })

        assert response.status_code == 200
        assert b'Invalid username or password' in response.data

    def test_login_post_missing_fields(self, client):
        """Test login with missing fields"""
        response = client.post('/login', data={
            'username': '',
            'password': 'password123'
        })

        assert response.status_code == 200
        assert b'Please enter both username and password' in response.data

    def test_register_page_get(self, client):
        """Test registration page loads correctly"""
        response = client.get('/register')
        assert response.status_code == 200
        assert b'Create Account' in response.data
        assert b'Password Requirements:' in response.data
        assert b'Email:' in response.data

    @patch('app.cognito_auth')
    def test_register_post_success(self, mock_cognito_auth, client):
        """Test successful registration"""
        mock_cognito_auth.sign_up_user.return_value = {
            'success': True,
            'user_sub': 'test-user-sub',
            'confirmation_required': True
        }

        response = client.post('/register', data={
            'username': 'newuser',
            'email': 'new@example.com',
            'password': 'Password123!',
            'confirm_password': 'Password123!',
            'first_name': 'New',
            'last_name': 'User'
        })

        assert response.status_code == 302
        assert '/confirm/newuser' in response.location

    def test_register_post_password_mismatch(self, client):
        """Test registration with password mismatch"""
        response = client.post('/register', data={
            'username': 'newuser',
            'email': 'new@example.com',
            'password': 'Password123!',
            'confirm_password': 'DifferentPassword!',
            'first_name': 'New',
            'last_name': 'User'
        })

        assert response.status_code == 200
        assert b'Passwords do not match' in response.data

    def test_register_post_weak_password(self, client):
        """Test registration with weak password"""
        response = client.post('/register', data={
            'username': 'newuser',
            'email': 'new@example.com',
            'password': '123',
            'confirm_password': '123'
        })

        assert response.status_code == 200
        assert b'Password must be at least 8 characters long' in response.data

    @patch('app.cognito_auth')
    def test_confirm_account_success(self, mock_cognito_auth, client):
        """Test successful account confirmation"""
        mock_cognito_auth.confirm_sign_up.return_value = {'success': True}

        response = client.post('/confirm/testuser', data={
            'username': 'testuser',
            'confirmation_code': '123456'
        })

        assert response.status_code == 302
        assert '/login' in response.location

    @patch('app.cognito_auth')
    def test_confirm_account_invalid_code(self, mock_cognito_auth, client):
        """Test account confirmation with invalid code"""
        mock_cognito_auth.confirm_sign_up.return_value = {
            'success': False,
            'error': 'Invalid verification code'
        }

        response = client.post('/confirm/testuser', data={
            'username': 'testuser',
            'confirmation_code': '000000'
        })

        assert response.status_code == 200
        assert b'Invalid verification code' in response.data

    def test_protected_route_without_login(self, client):
        """Test accessing protected route without login"""
        response = client.get('/dashboard')
        assert response.status_code == 302
        assert '/login' in response.location

    def test_logout(self, client):
        """Test logout functionality"""
        # First, simulate being logged in by setting session
        with client.session_transaction() as sess:
            sess['user'] = {'username': 'testuser'}

        response = client.get('/logout')
        assert response.status_code == 302
        assert '/login' in response.location

        # Verify session is cleared
        with client.session_transaction() as sess:
            assert 'user' not in sess


class TestAuthenticationFlow:
    """End-to-end authentication flow tests"""

    @pytest.fixture
    def app(self):
        """Create Flask app for testing"""
        from flask import Flask
        app = Flask(__name__)
        app.config.update(TEST_CONFIG)
        return app

    @pytest.fixture
    def client(self, app):
        """Create test client"""
        return app.test_client()

    @patch('app.cognito_auth')
    def test_complete_registration_flow(self, mock_cognito_auth, client):
        """Test complete user registration and confirmation flow"""
        # Step 1: Register user
        mock_cognito_auth.sign_up_user.return_value = {
            'success': True,
            'user_sub': 'test-user-sub',
            'confirmation_required': True
        }

        response = client.post('/register', data={
            'username': 'flowuser',
            'email': 'flow@example.com',
            'password': 'Password123!',
            'confirm_password': 'Password123!',
            'first_name': 'Flow',
            'last_name': 'User'
        })

        assert response.status_code == 302
        assert '/confirm/flowuser' in response.location

        # Step 2: Confirm account
        mock_cognito_auth.confirm_sign_up.return_value = {'success': True}

        response = client.post('/confirm/flowuser', data={
            'username': 'flowuser',
            'confirmation_code': '123456'
        })

        assert response.status_code == 302
        assert '/login' in response.location

        # Step 3: Login
        mock_cognito_auth.authenticate_user.return_value = {
            'success': True,
            'tokens': {
                'AccessToken': 'test-access-token',
                'RefreshToken': 'test-refresh-token',
                'ExpiresIn': 3600
            },
            'username': 'flowuser'
        }

        mock_cognito_auth.get_user_info.return_value = {
            'success': True,
            'username': 'flowuser',
            'attributes': {'email': 'flow@example.com', 'given_name': 'Flow'}
        }

        response = client.post('/login', data={
            'username': 'flowuser',
            'password': 'Password123!'
        })

        assert response.status_code == 302
        assert '/dashboard' in response.location


class TestErrorHandling:
    """Test error handling scenarios"""

    @pytest.fixture
    def cognito_auth(self):
        """Create CognitoAuth instance for testing"""
        return CognitoAuth(
            user_pool_id=TEST_CONFIG['COGNITO_USER_POOL_ID'],
            client_id=TEST_CONFIG['COGNITO_CLIENT_ID'],
            client_secret=TEST_CONFIG['COGNITO_CLIENT_SECRET'],
            region=TEST_CONFIG['COGNITO_REGION']
        )

    @patch('boto3.client')
    def test_network_error_handling(self, mock_boto_client, cognito_auth):
        """Test handling of network errors"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        cognito_auth.client = mock_client

        # Simulate network error
        mock_client.admin_initiate_auth.side_effect = Exception("Network error")

        result = cognito_auth.authenticate_user('testuser', 'password123')

        assert result['success'] is False
        assert 'Authentication failed' in result['error']

    @patch('boto3.client')
    def test_expired_code_handling(self, mock_boto_client, cognito_auth):
        """Test handling of expired confirmation codes"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        cognito_auth.client = mock_client

        error_response = {
            'Error': {
                'Code': 'ExpiredCodeException',
                'Message': 'Invalid code provided, please request a code again.'
            }
        }
        mock_client.confirm_sign_up.side_effect = ClientError(error_response, 'ConfirmSignUp')

        result = cognito_auth.confirm_sign_up('testuser', '123456')

        assert result['success'] is False
        assert result['error'] == 'Verification code has expired'


class TestFormValidation:
    """Test form validation"""

    @pytest.fixture
    def app(self):
        """Create Flask app for testing"""
        from flask import Flask
        app = Flask(__name__)
        app.config.update(TEST_CONFIG)
        return app

    @pytest.fixture
    def client(self, app):
        """Create test client"""
        return app.test_client()

    def test_empty_username_validation(self, client):
        """Test validation for empty username"""
        response = client.post('/login', data={
            'username': '   ',  # whitespace only
            'password': 'password123'
        })

        assert response.status_code == 200
        assert b'Please enter both username and password' in response.data

    def test_missing_email_validation(self, client):
        """Test validation for missing email in registration"""
        response = client.post('/register', data={
            'username': 'testuser',
            'email': '',
            'password': 'Password123!',
            'confirm_password': 'Password123!'
        })

        assert response.status_code == 200
        assert b'Please fill in all required fields' in response.data

    def test_confirmation_code_validation(self, client):
        """Test validation for empty confirmation code"""
        response = client.post('/confirm/testuser', data={
            'username': 'testuser',
            'confirmation_code': '   '  # whitespace only
        })

        assert response.status_code == 200
        assert b'Please enter the verification code' in response.data


# Test Configuration and Utilities
def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )


class TestUtilities:
    """Utility functions for testing"""

    @staticmethod
    def create_mock_tokens():
        """Create mock JWT tokens for testing"""
        return {
            'AccessToken': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test.token',
            'RefreshToken': 'refresh_token_string',
            'ExpiresIn': 3600
        }

    @staticmethod
    def create_mock_user_attributes():
        """Create mock user attributes"""
        return {
            'email': 'test@example.com',
            'given_name': 'Test',
            'family_name': 'User',
            'email_verified': 'true'
        }


if __name__ == '__main__':
    # Run tests if script is executed directly
    pytest.main([__file__, '-v'])