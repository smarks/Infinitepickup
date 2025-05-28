# AWS Cognito Flask Login Application

A complete web application that demonstrates user authentication using AWS Cognito with Flask. This application provides a full authentication system including user registration, email verification, secure login/logout, and protected routes.

## 🚀 Features

- **User Registration** with email verification
- **Secure Login/Logout** functionality
- **Protected Routes** with automatic token refresh
- **Session Management** with proper security
- **Password Strength Requirements** enforcement
- **Email Verification** workflow with resend capability
- **Comprehensive Error Handling** for all authentication scenarios
- **Responsive Web Interface** with clean styling
- **RESTful API Endpoints** for protected resources

## 📋 Prerequisites

- Python 3.7 or higher
- AWS Account with Cognito access
- AWS CLI configured (optional but recommended)

## 🛠️ Installation

1. **Clone or download the application code**

2. **Install required dependencies:**
   ```bash
   pip install flask boto3 python-jose[cryptography]
   ```

3. **Set up AWS credentials** (choose one method):
   - AWS CLI: `aws configure`
   - Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   - IAM roles (if running on EC2)

## ⚙️ AWS Cognito Configuration

### Step 1: Create a User Pool

1. Go to **AWS Cognito Console**
2. Click **Create user pool**
3. Configure the following settings:

**Authentication providers:**
- ✅ Email (required)
- ✅ Username (optional)

**Password policy (recommended):**
- Minimum length: 8 characters
- ✅ Require uppercase letters
- ✅ Require lowercase letters  
- ✅ Require numbers
- ✅ Require special characters

**Multi-factor authentication:**
- Optional (can be enabled for additional security)

**Email verification:**
- ✅ Send email verification messages
- ✅ Email address verification required

### Step 2: Create App Client

1. In your User Pool, go to **App integration**
2. Click **Create app client**
3. Configure:
   - **App client name:** Your app name
   - ✅ **Generate client secret** (IMPORTANT: Must be enabled)
   - **Authentication flows:**
     - ✅ ALLOW_ADMIN_USER_PASSWORD_AUTH
     - ✅ ALLOW_REFRESH_TOKEN_AUTH
4. **Save the following values:**
   - User Pool ID (format: `us-east-1_xxxxxxxxx`)
   - App Client ID
   - App Client Secret

## 🔧 Application Configuration

Set the following environment variables or update the code directly:

### Method 1: Environment Variables (Recommended)
```bash
export COGNITO_USER_POOL_ID='us-east-1_xxxxxxxxx'
export COGNITO_CLIENT_ID='your-app-client-id'
export COGNITO_CLIENT_SECRET='your-app-client-secret'
export COGNITO_REGION='us-east-1'
export SECRET_KEY='your-flask-secret-key-here'
```

### Method 2: Update Code Directly
Edit the configuration section in the application:
```python
app.config.update({
    'COGNITO_USER_POOL_ID': 'us-east-1_xxxxxxxxx',
    'COGNITO_CLIENT_ID': 'your-client-id',
    'COGNITO_CLIENT_SECRET': 'your-client-secret',
    'COGNITO_REGION': 'us-east-1',
    'SECRET_KEY': 'your-secret-key-here'
})
```

## 🚀 Running the Application

1. **Start the application:**
   ```bash
   python app.py
   ```

2. **Open your browser and navigate to:**
   ```
   http://localhost:5000
   ```

3. **You should see the startup output:**
   ```
   Starting AWS Cognito Flask Application...
   User Pool ID: us-east-1_xxxxxxxxx
   Client ID: your-client-id
   Region: us-east-1
   
   Features:
   - User Registration with Email Verification
   - Secure Login/Logout
   - Protected Routes with Token Refresh
   - Session Management
   
   Application will be available at: http://localhost:5000
   ```

## 🌐 Application Routes

| Route | Method | Description | Protection |
|-------|--------|-------------|------------|
| `/` | GET | Home page (redirects to login or dashboard) | Public |
| `/login` | GET, POST | User login form and authentication | Public |
| `/register` | GET, POST | User registration form | Public |
| `/confirm/<username>` | GET, POST | Email verification page | Public |
| `/resend-confirmation` | POST | Resend verification code | Public |
| `/dashboard` | GET | Main user dashboard | Protected |
| `/profile` | GET | User profile information (JSON) | Protected |
| `/api/protected` | GET | Protected API endpoint example | Protected |
| `/logout` | GET | Logout and clear session | Protected |

## 👤 User Registration Flow

1. **User visits `/register`**
2. **Fills out registration form:**
   - Username (required)
   - Email (required)
   - Password (required, must meet strength requirements)
   - Confirm Password (required)
   - First Name (optional)
   - Last Name (optional)

3. **AWS Cognito sends verification email**
4. **User redirected to `/confirm/<username>`**
5. **User enters 6-digit verification code**
6. **Account confirmed - ready for login**

## 🔐 Password Requirements

- **Minimum 8 characters**
- **At least one uppercase letter**
- **At least one lowercase letter**
- **At least one number**
- **At least one special character**

## 🔒 Security Features

- **Secure session management** with automatic expiration
- **Token-based authentication** with AWS Cognito
- **Automatic token refresh** for expired access tokens
- **Protected route decorator** (`@login_required`)
- **CSRF protection** via Flask sessions
- **Input validation** and sanitization
- **Comprehensive error handling**

## 🛡️ API Usage Examples

### Protected API Endpoint
```bash
# Must be logged in first, then access:
curl -X GET http://localhost:5000/api/protected \
     -H "Cookie: session=your-session-cookie"
```

**Response:**
```json
{
  "message": "This is a protected API endpoint",
  "user": "your-username",
  "timestamp": "2024-01-15T10:30:00",
  "authenticated_via": "AWS Cognito"
}
```

### User Profile Endpoint
```bash
curl -X GET http://localhost:5000/profile \
     -H "Cookie: session=your-session-cookie"
```

## 🐛 Troubleshooting

### Common Issues

**1. "Missing required configuration" error:**
- Ensure all environment variables are set correctly
- Check that your Cognito User Pool ID and Client ID are valid

**2. "Authentication failed" errors:**
- Verify your Cognito app client has a client secret
- Ensure ALLOW_ADMIN_USER_PASSWORD_AUTH is enabled
- Check that your AWS credentials have Cognito permissions

**3. "Email verification not working":**
- Confirm your User Pool has email verification enabled
- Check your email spam/junk folder
- Verify the email attribute is marked as required

**4. "Invalid password" errors:**
- Ensure password meets the strength requirements
- Check your Cognito password policy matches the application requirements

### Debug Mode
Run with debug enabled for detailed error messages:
```bash
python app.py
# Debug mode is enabled by default in the application
```

## 📱 Testing the Application

### Manual Testing Steps

1. **Registration Test:**
   - Go to `/register`
   - Create a new account
   - Check email for verification code
   - Confirm account at `/confirm/<username>`

2. **Login Test:**
   - Go to `/login`
   - Use registered credentials
   - Verify redirect to dashboard

3. **Protection Test:**
   - Try accessing `/dashboard` without login
   - Should redirect to login page

4. **Session Test:**
   - Login and wait for token expiration
   - Access protected route - should auto-refresh token

## 🔧 Customization

### Adding New Protected Routes
```python
@app.route('/my-protected-route')
@login_required
def my_protected_route():
    return f"Hello {session['user']['username']}!"
```

### Modifying User Attributes
Update the `sign_up_user` method in the `CognitoAuth` class to include additional attributes:
```python
user_attributes = [
    {'Name': 'email', 'Value': email},
    {'Name': 'phone_number', 'Value': phone_number},
    # Add more attributes as needed
]
```

## 📚 Additional Resources

- [AWS Cognito Documentation](https://docs.aws.amazon.com/cognito/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Boto3 Cognito Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html)

## 📄 License

This application is provided as-is for educational and development purposes. Make sure to implement additional security measures for production use.

## 🤝 Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## 🧪 Testing

The application includes a comprehensive test suite with unit tests, integration tests, and end-to-end authentication flow testing.

### Quick Test Setup

1. **Save the test files:**
   - Copy the **"test_app.py - Clean Test Suite"** artifact above and save as `test_app.py`
   - Copy the **"conftest.py - Test Configuration"** artifact above and save as `conftest.py`  
   - Copy the **"requirements-test.txt"** from the requirements artifact and save as `requirements-test.txt`
   - Copy the **"pytest.ini"** from the requirements artifact and save as `pytest.ini`

2. **Your file structure should look like:**
   ```
   your-project/
   ├── app.py                # Your main Flask app (from first artifact)
   ├── test_app.py          # Test suite (imports from app.py)
   ├── conftest.py          # Test fixtures
   ├── pytest.ini          # Test configuration
   └── requirements-test.txt # Test dependencies
   ```

### Test Setup

1. **Install test dependencies:**
   ```bash
   pip install -r requirements-test.txt
   # Or manually:
   # pip install pytest pytest-mock pytest-flask pytest-cov moto[cognitoidp]
   ```

2. **Run all tests:**
   ```bash
   pytest
   # or using make:
   make test
   ```

3. **Run with coverage report:**
   ```bash
   pytest --cov=app --cov-report=html --cov-report=term-missing
   # or using make:
   make test-coverage
   ```

### Test Categories

**Unit Tests (`TestCognitoAuth`):**
- CognitoAuth class methods
- Secret hash calculation
- AWS API response handling
- Error scenarios

**Integration Tests (`TestFlaskRoutes`):**
- Flask route behavior
- Form validation
- Session management
- Authentication flows

**End-to-End Tests (`TestAuthenticationFlow`):**
- Complete registration → confirmation → login flow
- Multi-step user journeys

**Error Handling Tests (`TestErrorHandling`):**
- Network errors
- Invalid credentials
- Expired codes
- Malformed requests

### Running Specific Tests

```bash
# Run only unit tests
pytest test_app.py::TestCognitoAuth -v
# or: make test-unit

# Run only route tests  
pytest test_app.py::TestFlaskRoutes -v
# or: make test-routes

# Run authentication flow tests
pytest test_app.py::TestAuthenticationFlow -v
# or: make test-auth

# Run specific test method
pytest test_app.py::TestCognitoAuth::test_authenticate_user_success -v

# Run tests with markers
pytest -m "unit" -v
pytest -m "integration" -v

# Run excluding slow tests
pytest -m "not slow" -v
# or: make test-fast

# Run tests in parallel (faster)
pytest -n auto
# or: make test-parallel
```

### Test Configuration

The test suite uses:
- **Mocked AWS services** (no real AWS calls)
- **Isolated test environment** with test configuration
- **Comprehensive fixtures** for common test data
- **Parametrized tests** for multiple scenarios

### Coverage Report

Generate HTML coverage report:
```bash
pytest --cov=app --cov-report=html
open htmlcov/index.html
```

### Test Structure

```
your-project/
├── app.py                   # Main Flask application
├── test_app.py             # Complete test suite
├── conftest.py             # Test fixtures and configuration
├── pytest.ini             # Pytest settings
├── requirements.txt        # App dependencies
├── requirements-test.txt   # Test dependencies
├── Makefile               # Test commands
├── .coveragerc            # Coverage configuration
└── README.md              # This file
```

### Continuous Integration

The project includes GitHub Actions workflow for:
- **Multi-Python version testing** (3.8, 3.9, 3.10, 3.11)
- **Automated testing** on push/PR
- **Coverage reporting** via Codecov
- **Code quality checks** with flake8, black, isort

### Test Examples

**Testing Registration Flow:**
```python
def test_complete_registration_flow(mock_cognito_auth, client):
    # 1. Register user
    response = client.post('/register', data={...})
    assert response.status_code == 302
    
    # 2. Confirm account  
    response = client.post('/confirm/user', data={...})
    assert response.status_code == 302
    
    # 3. Login
    response = client.post('/login', data={...})
    assert '/dashboard' in response.location
```

**Testing Error Scenarios:**
```python
def test_invalid_credentials(mock_cognito_auth, client):
    mock_cognito_auth.authenticate_user.return_value = {
        'success': False, 
        'error': 'Invalid username or password'
    }
    response = client.post('/login', data={...})
    assert b'Invalid username or password' in response.data
```

---

**Note:** This application demonstrates AWS Cognito integration patterns and includes comprehensive testing. For production use, consider implementing additional security measures such as rate limiting, HTTPS enforcement, and comprehensive logging.