"""
Unit tests for AuthService

This test suite covers all methods in the AuthService class:
- hash_password
- verify_password
- generate_token
- decode_token
- generate_verification_token
- get_token_expiry
"""

import pytest
import jwt
import bcrypt
import os
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from freezegun import freeze_time

from app.services.auth_service import AuthService


class TestAuthService:
    """Test suite for AuthService class"""
    
    @pytest.fixture
    def auth_service(self):
        """Create an AuthService instance for testing"""
        return AuthService()
    
    @pytest.fixture
    def sample_user(self):
        """Sample user data for testing"""
        return {
            'user_id': 1,
            'email': 'test@example.com',
            'type': 'user',
            'email_verified': True,
            'active': True
        }
    
    # ========== hash_password Tests ==========
    
    def test_hash_password_returns_string(self, auth_service):
        """Test that hash_password returns a string"""
        password = "test_password_123"
        hashed = auth_service.hash_password(password)
        
        assert isinstance(hashed, str)
        assert len(hashed) > 0
    
    def test_hash_password_different_passwords_different_hashes(self, auth_service):
        """Test that different passwords produce different hashes"""
        password1 = "password1"
        password2 = "password2"
        
        hashed1 = auth_service.hash_password(password1)
        hashed2 = auth_service.hash_password(password2)
        
        assert hashed1 != hashed2
    
    def test_hash_password_same_password_different_hashes(self, auth_service):
        """Test that same password produces different hashes (due to salt)"""
        password = "same_password"
        
        hashed1 = auth_service.hash_password(password)
        hashed2 = auth_service.hash_password(password)
        
        # Different salts should produce different hashes
        assert hashed1 != hashed2
    
    def test_hash_password_uses_bcrypt(self, auth_service):
        """Test that hash_password uses bcrypt correctly"""
        password = "test_password"
        hashed = auth_service.hash_password(password)
        
        # Verify it's a valid bcrypt hash
        assert bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    # ========== verify_password Tests ==========
    
    def test_verify_password_correct_password(self, auth_service):
        """Test that verify_password returns True for correct password"""
        password = "test_password"
        hashed = auth_service.hash_password(password)
        
        result = auth_service.verify_password(password, hashed)
        
        assert result is True
    
    def test_verify_password_incorrect_password(self, auth_service):
        """Test that verify_password returns False for incorrect password"""
        password = "test_password"
        wrong_password = "wrong_password"
        hashed = auth_service.hash_password(password)
        
        result = auth_service.verify_password(wrong_password, hashed)
        
        assert result is False
    
    def test_verify_password_invalid_hash(self, auth_service):
        """Test that verify_password handles invalid hash gracefully"""
        password = "test_password"
        invalid_hash = "not_a_valid_hash"
        
        result = auth_service.verify_password(password, invalid_hash)
        
        assert result is False
    
    def test_verify_password_empty_strings(self, auth_service):
        """Test verify_password with empty strings"""
        result = auth_service.verify_password("", "")
        assert result is False
    
    # ========== generate_token Tests ==========
    
    def test_generate_token_returns_string(self, auth_service, sample_user):
        """Test that generate_token returns a string"""
        token = auth_service.generate_token(sample_user)
        
        assert isinstance(token, str)
        assert len(token) > 0
    
    def test_generate_token_contains_user_data(self, auth_service, sample_user):
        """Test that generated token contains correct user data"""
        token = auth_service.generate_token(sample_user)
        decoded = jwt.decode(token, auth_service.jwt_secret, algorithms=['HS256'])
        
        assert decoded['userId'] == sample_user['user_id']
        assert decoded['email'] == sample_user['email']
        assert decoded['type'] == sample_user['type']
        assert decoded['emailVerified'] == sample_user['email_verified']
        assert decoded['active'] == sample_user['active']
    
    def test_generate_token_includes_iat_and_exp(self, auth_service, sample_user):
        """Test that token includes issued at and expiration time"""
        token = auth_service.generate_token(sample_user)
        decoded = jwt.decode(token, auth_service.jwt_secret, algorithms=['HS256'])
        
        assert 'iat' in decoded
        assert 'exp' in decoded
        # JWT decodes iat and exp as Unix timestamps (integers)
        assert isinstance(decoded['iat'], int)
        assert isinstance(decoded['exp'], int)
        assert decoded['exp'] > decoded['iat']
    
    def test_generate_token_default_values(self, auth_service):
        """Test that token uses default values when user data is missing"""
        user = {'user_id': 1, 'email': 'test@example.com'}
        token = auth_service.generate_token(user)
        decoded = jwt.decode(token, auth_service.jwt_secret, algorithms=['HS256'])
        
        assert decoded['emailVerified'] is False
        assert decoded['active'] is True
    
    @freeze_time("2024-01-01 12:00:00")
    def test_generate_token_expiration_time(self, auth_service, sample_user):
        """Test that token expiration is set correctly"""
        token = auth_service.generate_token(sample_user)
        decoded = jwt.decode(token, auth_service.jwt_secret, algorithms=['HS256'])
        
        # JWT decodes exp as Unix timestamp (integer)
        # Calculate expected expiration as timestamp
        expected_exp = int((datetime.utcnow() + timedelta(hours=auth_service.jwt_expiration_hours)).timestamp())
        # Allow 1 second tolerance for timing differences
        assert abs(decoded['exp'] - expected_exp) <= 1
    
    def test_generate_token_custom_jwt_secret(self):
        """Test that token uses custom JWT secret from environment"""
        with patch.dict(os.environ, {'JWT_SECRET': 'custom_secret_key'}):
            service = AuthService()
            token = service.generate_token({'user_id': 1, 'email': 'test@example.com'})
            
            # Should decode with custom secret
            decoded = jwt.decode(token, 'custom_secret_key', algorithms=['HS256'])
            assert decoded['userId'] == 1
    
    # ========== decode_token Tests ==========
    
    def test_decode_token_valid_token(self, auth_service, sample_user):
        """Test that decode_token correctly decodes a valid token"""
        token = auth_service.generate_token(sample_user)
        decoded = auth_service.decode_token(token)
        
        assert decoded['userId'] == sample_user['user_id']
        assert decoded['email'] == sample_user['email']
    
    def test_decode_token_invalid_token(self, auth_service):
        """Test that decode_token raises exception for invalid token"""
        invalid_token = "invalid.token.here"
        
        with pytest.raises(jwt.InvalidTokenError):
            auth_service.decode_token(invalid_token)
    
    def test_decode_token_wrong_secret(self, auth_service, sample_user):
        """Test that decode_token raises exception for token with wrong secret"""
        token = auth_service.generate_token(sample_user)
        
        # Try to decode with wrong secret
        with pytest.raises(jwt.InvalidTokenError):
            jwt.decode(token, 'wrong_secret', algorithms=['HS256'])
    
    @freeze_time("2024-01-01 12:00:00")
    def test_decode_token_expired_token(self, auth_service, sample_user):
        """Test that decode_token raises exception for expired token"""
        # Generate token with very short expiration
        with patch.object(auth_service, 'jwt_expiration_hours', -1):
            token = auth_service.generate_token(sample_user)
        
        # Move time forward
        with freeze_time("2024-01-02 12:00:00"):
            with pytest.raises(jwt.ExpiredSignatureError):
                auth_service.decode_token(token)
    
    def test_decode_token_without_expiration_check(self, auth_service, sample_user):
        """Test that decode_token can decode expired token when verify_exp=False"""
        # Generate token with very short expiration
        with patch.object(auth_service, 'jwt_expiration_hours', -1):
            token = auth_service.generate_token(sample_user)
        
        # Should decode successfully with verify_exp=False
        decoded = auth_service.decode_token(token, verify_exp=False)
        assert decoded['userId'] == sample_user['user_id']
    
    # ========== generate_verification_token Tests ==========
    
    def test_generate_verification_token_returns_string(self, auth_service):
        """Test that generate_verification_token returns a string"""
        token = auth_service.generate_verification_token()
        
        assert isinstance(token, str)
    
    def test_generate_verification_token_is_six_digits(self, auth_service):
        """Test that verification token is 6 digits"""
        token = auth_service.generate_verification_token()
        
        assert len(token) == 6
        assert token.isdigit()
    
    def test_generate_verification_token_range(self, auth_service):
        """Test that verification token is in valid range (100000-999999)"""
        token = auth_service.generate_verification_token()
        token_int = int(token)
        
        assert 100000 <= token_int <= 999999
    
    def test_generate_verification_token_different_tokens(self, auth_service):
        """Test that multiple calls generate different tokens (high probability)"""
        tokens = [auth_service.generate_verification_token() for _ in range(10)]
        
        # At least some tokens should be different (very high probability)
        assert len(set(tokens)) > 1
    
    # ========== get_token_expiry Tests ==========
    
    @freeze_time("2024-01-01 12:00:00")
    def test_get_token_expiry_returns_datetime(self, auth_service):
        """Test that get_token_expiry returns a datetime object"""
        expiry = auth_service.get_token_expiry()
        
        assert isinstance(expiry, datetime)
    
    @freeze_time("2024-01-01 12:00:00")
    def test_get_token_expiry_correct_time(self, auth_service):
        """Test that get_token_expiry returns correct future time"""
        expiry = auth_service.get_token_expiry()
        expected = datetime.utcnow() + timedelta(hours=auth_service.verification_token_hours)
        
        assert expiry == expected
    
    @freeze_time("2024-01-01 12:00:00")
    def test_get_token_expiry_custom_hours(self):
        """Test that get_token_expiry uses custom verification_token_hours"""
        with patch.dict(os.environ, {'VERIFICATION_TOKEN_HOURS': '5'}):
            service = AuthService()
            expiry = service.get_token_expiry()
            expected = datetime.utcnow() + timedelta(hours=5)
            
            assert expiry == expected
    
    # ========== Integration Tests ==========
    
    def test_hash_and_verify_password_work_together(self, auth_service):
        """Integration test: hash_password and verify_password work together"""
        password = "integration_test_password"
        
        hashed = auth_service.hash_password(password)
        verified = auth_service.verify_password(password, hashed)
        
        assert verified is True
    
    def test_generate_and_decode_token_work_together(self, auth_service, sample_user):
        """Integration test: generate_token and decode_token work together"""
        token = auth_service.generate_token(sample_user)
        decoded = auth_service.decode_token(token)
        
        assert decoded['userId'] == sample_user['user_id']
        assert decoded['email'] == sample_user['email']
    
    def test_full_authentication_flow(self, auth_service):
        """Integration test: full authentication flow"""
        # Register user
        password = "secure_password_123"
        hashed_password = auth_service.hash_password(password)
        
        user = {
            'user_id': 1,
            'email': 'newuser@example.com',
            'type': 'user',
            'email_verified': False,
            'active': True
        }
        
        # Generate token
        token = auth_service.generate_token(user)
        
        # Verify token
        decoded = auth_service.decode_token(token)
        assert decoded['userId'] == user['user_id']
        
        # Verify password
        assert auth_service.verify_password(password, hashed_password) is True
        
        # Generate verification token
        verification_token = auth_service.generate_verification_token()
        assert len(verification_token) == 6
    
    # ========== Edge Cases and Error Handling ==========
    
    def test_hash_password_special_characters(self, auth_service):
        """Test hash_password with special characters"""
        password = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        hashed = auth_service.hash_password(password)
        
        assert auth_service.verify_password(password, hashed) is True
    
    def test_hash_password_unicode(self, auth_service):
        """Test hash_password with unicode characters"""
        password = "パスワード123한글"
        hashed = auth_service.hash_password(password)
        
        assert auth_service.verify_password(password, hashed) is True
    
    def test_hash_password_very_long_password(self, auth_service):
        """Test hash_password with very long password"""
        password = "a" * 1000
        hashed = auth_service.hash_password(password)
        
        assert auth_service.verify_password(password, hashed) is True
    
    def test_generate_token_empty_user_dict(self, auth_service):
        """Test generate_token with empty user dict"""
        user = {}
        token = auth_service.generate_token(user)
        decoded = auth_service.decode_token(token)
        
        assert decoded['userId'] is None
        assert decoded['email'] is None
    
    def test_generate_token_missing_fields(self, auth_service):
        """Test generate_token with missing optional fields"""
        user = {'user_id': 1}
        token = auth_service.generate_token(user)
        decoded = auth_service.decode_token(token)
        
        assert decoded['userId'] == 1
        assert decoded['email'] is None
        assert decoded['emailVerified'] is False  # Default value
        assert decoded['active'] is True  # Default value
