# pytest.ini
[tool: pytest]
testpaths = tests
python_files = test_ *.py
python_classes = Test *
python_functions = test_ *
addopts =
-v
--tb = short
--strict - markers
--disable - warnings
--color = yes
markers =
slow: marks
tests as slow(deselect
with -m "not slow")
integration: marks
tests as integration
tests
unit: marks
tests as unit
tests
auth: marks
tests
related
to
authentication
routes: marks
tests
related
to
Flask
routes

# conftest.py - Shared test fixtures
import pytest
import os
from unittest.mock import Mock, patch
import boto3
from moto import mock_cognitoidp

# Test environment variables
os.environ.update({
    'COGNITO_USER_POOL_ID': 'us-east-1_test123456',
    'COGNITO_CLIENT_ID': 'test-client-id',
    'COGNITO_CLIENT_SECRET': 'test-client-secret',
    'COGNITO_REGION': 'us-east-1',
    'SECRET_KEY': 'test-secret-key'
})


@pytest.fixture
def mock_cognito_service():
    """Mock AWS Cognito service for testing"""
    with mock_cognitoidp():
        yield


@pytest.fixture
def sample_user_data():
    """Sample user data for testing"""
    return {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'Password123!',
        'first_name': 'Test',
        'last_name': 'User'
    }


@pytest.fixture
def sample_tokens():
    """Sample JWT tokens for testing"""
    return {
        'AccessToken': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test.access.token',
        'RefreshToken': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test.refresh.token',
        'IdToken': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test.id.token',
        'ExpiresIn': 3600,
        'TokenType': 'Bearer'
    }


@pytest.fixture
def authenticated_session():
    """Create an authenticated session for testing"""
    return {
        'user': {
            'username': 'testuser',
            'attributes': {
                'email': 'test@example.com',
                'given_name': 'Test',
                'family_name': 'User'
            }
        },
        'access_token': 'test-access-token',
        'refresh_token': 'test-refresh-token',
        'login_time': '2024-01-15T10:30:00.000000'
    }


# requirements-test.txt
pytest >= 7.0
.0
pytest - mock >= 3.10
.0
pytest - flask >= 1.2
.0
pytest - cov >= 4.0
.0
moto[cognitoidp] >= 4.2
.0
responses >= 0.23
.0
freezegun >= 1.2
.0

# Makefile for common test commands
.PHONY: test
test - unit
test - integration
test - auth
test - coverage
clean

# Run all tests
test:
pytest

# Run only unit tests
test - unit:
pytest - m
"unit"

# Run only integration tests
test - integration:
pytest - m
"integration"

# Run authentication related tests
test - auth:
pytest - m
"auth"

# Run tests with coverage report
test - coverage:
pytest - -cov = app - -cov - report = html - -cov - report = term - missing

# Run tests in parallel (requires pytest-xdist)
test - parallel:
pytest - n
auto

# Run specific test file
test - cognito:
pytest
test_cognito_auth.py - v

# Run tests excluding slow ones
test - fast:
pytest - m
"not slow"

# Clean test artifacts
clean:
rm - rf.pytest_cache /
rm - rf
htmlcov /
rm - rf.coverage
find. - type
d - name
__pycache__ - exec
rm - rf
{} +
find. - type
f - name
"*.pyc" - delete

# tox.ini - Test across multiple Python versions
[tox]
envlist = py37, py38, py39, py310, py311
isolated_build = true

[testenv]
deps =
-r
requirements - test.txt
commands =
pytest
{posargs}

[testenv: coverage]
deps =
-r
requirements - test.txt
commands =
pytest - -cov = app - -cov - report = html - -cov - report = term - missing

[testenv: lint]
deps =
flake8
black
isort
commands =
flake8
app.py
test_ *.py
black - -check
app.py
test_ *.py
isort - -check - only
app.py
test_ *.py

# GitHub Actions workflow file (.github/workflows/test.yml)
name: Tests

on:
push:
branches: [main, develop]
pull_request:
branches: [main]

jobs:
test:
runs - on: ubuntu - latest
strategy:
matrix:
python - version: ['3.8', '3.9', '3.10', '3.11']

steps:
- uses: actions / checkout @ v3

- name: Set
up
Python ${{matrix.python - version}}
uses: actions / setup - python @ v4
with:
    python - version: ${{matrix.python - version}}

- name: Install
dependencies
run: |
python - m
pip
install - -upgrade
pip
pip
install - r
requirements.txt
pip
install - r
requirements - test.txt

- name: Run
tests
run: |
pytest - -cov = app - -cov - report = xml

- name: Upload
coverage
to
Codecov
uses: codecov / codecov - action @ v3
with:
    file:./ coverage.xml
    flags: unittests
    name: codecov - umbrella