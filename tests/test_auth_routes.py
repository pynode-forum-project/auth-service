"""
API Integration Tests for Auth Service Routes

Tests the HTTP endpoints using Flask test client:
- POST /login
- POST /register
- POST /verify-email
- POST /resend-verification
- POST /refresh-token
- GET /health
"""

import pytest
from unittest.mock import patch, MagicMock
from app import create_app


@pytest.fixture
def app():
    """Create Flask app for testing"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['JWT_SECRET'] = 'test-jwt-secret-key'
    return app


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def mock_user_client():
    """Mock UserClient"""
    with patch('app.routes.auth_routes.user_client') as mock:
        yield mock


@pytest.fixture
def mock_message_queue():
    """Mock MessageQueue"""
    with patch('app.routes.auth_routes.message_queue') as mock:
        yield mock


@pytest.fixture
def mock_auth_service():
    """Mock AuthService"""
    with patch('app.routes.auth_routes.auth_service') as mock:
        yield mock


@pytest.fixture(autouse=True)
def setup_mocks(mock_user_client, mock_message_queue, mock_auth_service):
    """Auto-setup mocks for all tests"""
    pass


class TestLoginEndpoint:
    """Test POST /login endpoint"""
    
    def test_login_success(self, client, mock_user_client, mock_auth_service):
        """Test successful login returns 200 and token"""
        # Mock user data
        mock_user = {
            'user_id': 1,
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'hashed_password',
            'type': 'user',
            'active': True,
            'email_verified': True,
            'pending_email': None,
            'profile_image_url': None
        }
        
        mock_user_client.get_user_by_email.return_value = mock_user
        mock_auth_service.verify_password.return_value = True
        mock_auth_service.generate_token.return_value = 'test-jwt-token'
        
        response = client.post('/login', json={
            'email': 'test@example.com',
            'password': 'password123'
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'Login successful'
        assert 'token' in data
        assert data['token'] == 'test-jwt-token'
        assert 'user' in data
        assert data['user']['email'] == 'test@example.com'
    
    def test_login_invalid_email(self, client, mock_user_client):
        """Test login with non-existent email returns 401"""
        mock_user_client.get_user_by_email.return_value = None
        
        response = client.post('/login', json={
            'email': 'nonexistent@example.com',
            'password': 'password123'
        })
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'error' in data
    
    def test_login_invalid_password(self, client, mock_user_client, mock_auth_service):
        """Test login with wrong password returns 401"""
        mock_user = {
            'user_id': 1,
            'email': 'test@example.com',
            'password': 'hashed_password',
            'active': True
        }
        
        mock_user_client.get_user_by_email.return_value = mock_user
        mock_auth_service.verify_password.return_value = False
        
        response = client.post('/login', json={
            'email': 'test@example.com',
            'password': 'wrong_password'
        })
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'error' in data
    
    def test_login_banned_account(self, client, mock_user_client):
        """Test login with banned account returns 403"""
        mock_user = {
            'user_id': 1,
            'email': 'test@example.com',
            'password': 'hashed_password',
            'active': False
        }
        
        mock_user_client.get_user_by_email.return_value = mock_user
        
        response = client.post('/login', json={
            'email': 'test@example.com',
            'password': 'password123'
        })
        
        assert response.status_code == 403
        data = response.get_json()
        assert 'error' in data
        assert 'banned' in data['error'].lower()
    
    def test_login_validation_error(self, client):
        """Test login with missing fields returns 400"""
        response = client.post('/login', json={
            'email': 'test@example.com'
            # Missing password
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data


class TestRegisterEndpoint:
    """Test POST /register endpoint"""
    
    def test_register_success(self, client, mock_user_client, mock_auth_service, mock_message_queue):
        """Test successful registration returns 201"""
        # Mock no existing user
        mock_user_client.get_user_by_email.return_value = None
        mock_user_client.get_user_by_pending_email.return_value = None
        
        # Mock new user creation
        new_user = {
            'user_id': 1,
            'email': 'newuser@example.com',
            'first_name': 'Jane',
            'last_name': 'Smith',
            'type': 'user',
            'pending_email': None
        }
        mock_user_client.create_user.return_value = new_user
        
        mock_auth_service.hash_password.return_value = 'hashed_password'
        mock_auth_service.generate_verification_token.return_value = '123456'
        mock_auth_service.get_token_expiry.return_value = MagicMock(isoformat=lambda: '2026-01-28T10:00:00')
        mock_auth_service.generate_token.return_value = 'test-jwt-token'
        
        response = client.post('/register', json={
            'firstName': 'Jane',
            'lastName': 'Smith',
            'email': 'newuser@example.com',
            'password': 'Password123!'
        })
        
        assert response.status_code == 201
        data = response.get_json()
        assert 'message' in data
        assert 'token' in data
        assert 'user' in data
        mock_message_queue.send_verification_email.assert_called_once()
    
    def test_register_duplicate_email(self, client, mock_user_client):
        """Test registration with existing email returns 409"""
        mock_user_client.get_user_by_email.return_value = {
            'user_id': 1,
            'email': 'existing@example.com'
        }
        
        response = client.post('/register', json={
            'firstName': 'Jane',
            'lastName': 'Smith',
            'email': 'existing@example.com',
            'password': 'Password123!'
        })
        
        assert response.status_code == 409
        data = response.get_json()
        assert 'error' in data
    
    def test_register_validation_error(self, client):
        """Test registration with invalid data returns 400"""
        response = client.post('/register', json={
            'firstName': 'Jane',
            # Missing required fields
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data


class TestVerifyEmailEndpoint:
    """Test POST /verify-email endpoint"""
    
    def test_verify_email_success(self, client, mock_user_client, mock_auth_service):
        """Test successful email verification returns 200"""
        verification_result = {
            'success': True,
            'user': {
                'userId': 1,
                'email': 'test@example.com',
                'firstName': 'John',
                'lastName': 'Doe',
                'type': 'user',
                'active': True,
                'emailVerified': True,
                'profileImageUrl': None,
                'pendingEmail': None
            }
        }
        
        mock_user_client.verify_email.return_value = verification_result
        mock_auth_service.generate_token.return_value = 'new-jwt-token'
        
        response = client.post('/verify-email', json={
            'email': 'test@example.com',
            'token': '123456'
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'Email verified successfully'
        assert 'token' in data
        assert 'user' in data
    
    def test_verify_email_invalid_token(self, client, mock_user_client):
        """Test verification with invalid token returns 400"""
        mock_user_client.verify_email.return_value = {
            'success': False,
            'message': 'Invalid or expired token'
        }
        
        response = client.post('/verify-email', json={
            'email': 'test@example.com',
            'token': 'invalid_token'
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
    
    def test_verify_email_missing_fields(self, client):
        """Test verification with missing fields returns 400"""
        response = client.post('/verify-email', json={
            'email': 'test@example.com'
            # Missing token
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data


class TestResendVerificationEndpoint:
    """Test POST /resend-verification endpoint"""
    
    def test_resend_verification_success(self, client, mock_user_client, mock_auth_service, mock_message_queue):
        """Test successful resend verification returns 200"""
        mock_user = {
            'user_id': 1,
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'email_verified': False,
            'pending_email': None
        }
        
        mock_user_client.get_user_by_email.return_value = mock_user
        mock_user_client.get_valid_verification_token.return_value = {'token': '123456'}
        
        response = client.post('/resend-verification', json={
            'email': 'test@example.com'
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'Verification email sent'
        mock_message_queue.send_verification_email.assert_called_once()
    
    def test_resend_verification_user_not_found(self, client, mock_user_client):
        """Test resend verification with non-existent user returns 404"""
        mock_user_client.get_user_by_email.return_value = None
        mock_user_client.get_user_by_pending_email.return_value = None
        
        response = client.post('/resend-verification', json={
            'email': 'nonexistent@example.com'
        })
        
        assert response.status_code == 404
        data = response.get_json()
        assert 'error' in data
    
    def test_resend_verification_already_verified(self, client, mock_user_client):
        """Test resend verification for already verified email returns 400"""
        mock_user = {
            'user_id': 1,
            'email': 'test@example.com',
            'email_verified': True,
            'pending_email': None
        }
        
        mock_user_client.get_user_by_email.return_value = mock_user
        
        response = client.post('/resend-verification', json={
            'email': 'test@example.com'
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data


class TestRefreshTokenEndpoint:
    """Test POST /refresh-token endpoint"""
    
    def test_refresh_token_success(self, client, mock_user_client, mock_auth_service):
        """Test successful token refresh returns 200"""
        mock_user = {
            'user_id': 1,
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'type': 'user',
            'active': True,
            'email_verified': True
        }
        
        mock_auth_service.decode_token.return_value = {'userId': 1}
        mock_user_client.get_user_by_id.return_value = mock_user
        mock_auth_service.generate_token.return_value = 'new-jwt-token'
        
        response = client.post('/refresh-token', headers={
            'Authorization': 'Bearer old-token'
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'Token refreshed'
        assert 'token' in data
        assert data['token'] == 'new-jwt-token'
    
    def test_refresh_token_no_auth_header(self, client):
        """Test refresh token without Authorization header returns 401"""
        response = client.post('/refresh-token')
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'error' in data
    
    def test_refresh_token_invalid_token(self, client, mock_auth_service):
        """Test refresh token with invalid token returns 401"""
        mock_auth_service.decode_token.side_effect = Exception('Invalid token')
        
        response = client.post('/refresh-token', headers={
            'Authorization': 'Bearer invalid-token'
        })
        
        assert response.status_code == 401
        data = response.get_json()
        assert 'error' in data
    
    def test_refresh_token_banned_user(self, client, mock_user_client, mock_auth_service):
        """Test refresh token for banned user returns 403"""
        mock_auth_service.decode_token.return_value = {'userId': 1}
        mock_user_client.get_user_by_id.return_value = {
            'user_id': 1,
            'active': False
        }
        
        response = client.post('/refresh-token', headers={
            'Authorization': 'Bearer old-token'
        })
        
        assert response.status_code == 403
        data = response.get_json()
        assert 'error' in data


class TestHealthEndpoint:
    """Test GET /health endpoint"""
    
    def test_health_check(self, client):
        """Test health endpoint returns 200"""
        response = client.get('/health')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'
        assert data['service'] == 'auth-service'
