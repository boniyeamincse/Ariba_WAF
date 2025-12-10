"""
Token Service Module

Provides JWT token generation, validation, and management.
"""

import jwt
import uuid
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from config_manager import config_manager

class TokenService:
    """
    Token service for JWT token generation and validation.
    """

    def __init__(self):
        self.logger = logging.getLogger('auth.token_service')
        self.config = config_manager.get_config('authentication')

        # Load JWT configuration
        self.secret_key = self.config.get('jwt_secret_key', 'default-secret-key-change-me')
        self.algorithm = self.config.get('jwt_algorithm', 'HS256')
        self.access_token_expiration = self.config.get('access_token_expiration_minutes', 15)
        self.refresh_token_expiration = self.config.get('refresh_token_expiration_days', 7)

        # Token issuer and audience
        self.issuer = self.config.get('jwt_issuer', 'ariba-waf')
        self.audience = self.config.get('jwt_audience', 'ariba-waf-client')

        self.logger.info(f"TokenService initialized with {self.algorithm} algorithm")

    def generate_access_token(self, user_id: int, username: str, roles: list, session_id: str) -> str:
        """
        Generate a new access token.

        Args:
            user_id: User ID
            username: Username
            roles: List of user roles
            session_id: Session ID

        Returns:
            JWT access token
        """
        now = datetime.utcnow()
        expiration = now + timedelta(minutes=self.access_token_expiration)

        payload = {
            'jti': str(uuid.uuid4()),  # Unique identifier for the token
            'sub': str(user_id),      # Subject (user ID)
            'username': username,
            'roles': roles,
            'session_id': session_id,
            'iat': int(now.timestamp()),  # Issued at
            'exp': int(expiration.timestamp()),  # Expiration time
            'iss': self.issuer,
            'aud': self.audience,
            'token_type': 'access'
        }

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def generate_refresh_token(self, user_id: int, session_id: str) -> str:
        """
        Generate a new refresh token.

        Args:
            user_id: User ID
            session_id: Session ID

        Returns:
            JWT refresh token
        """
        now = datetime.utcnow()
        expiration = now + timedelta(days=self.refresh_token_expiration)

        payload = {
            'jti': str(uuid.uuid4()),  # Unique identifier for the token
            'sub': str(user_id),      # Subject (user ID)
            'session_id': session_id,
            'iat': int(now.timestamp()),  # Issued at
            'exp': int(expiration.timestamp()),  # Expiration time
            'iss': self.issuer,
            'aud': self.audience,
            'token_type': 'refresh'
        }

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def generate_token_pair(self, user_id: int, username: str, roles: list, session_id: str) -> Dict[str, str]:
        """
        Generate both access and refresh tokens.

        Args:
            user_id: User ID
            username: Username
            roles: List of user roles
            session_id: Session ID

        Returns:
            Dictionary with access_token and refresh_token
        """
        return {
            'access_token': self.generate_access_token(user_id, username, roles, session_id),
            'refresh_token': self.generate_refresh_token(user_id, session_id)
        }

    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate and decode a JWT token.

        Args:
            token: JWT token to validate

        Returns:
            Decoded token payload

        Raises:
            jwt.ExpiredSignatureError: If token is expired
            jwt.InvalidTokenError: If token is invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience
            )

            # Verify required claims
            if 'jti' not in payload:
                raise jwt.InvalidTokenError("Missing jti claim")
            if 'sub' not in payload:
                raise jwt.InvalidTokenError("Missing sub claim")
            if 'iat' not in payload:
                raise jwt.InvalidTokenError("Missing iat claim")
            if 'exp' not in payload:
                raise jwt.InvalidTokenError("Missing exp claim")
            if 'token_type' not in payload:
                raise jwt.InvalidTokenError("Missing token_type claim")

            return payload

        except jwt.ExpiredSignatureError:
            self.logger.warning("Expired token validation attempt")
            raise
        except jwt.InvalidTokenError as e:
            self.logger.warning(f"Invalid token validation attempt: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Token validation error: {str(e)}")
            raise jwt.InvalidTokenError("Invalid token")

    def validate_access_token(self, token: str) -> Dict[str, Any]:
        """
        Validate an access token specifically.

        Args:
            token: Access token to validate

        Returns:
            Decoded token payload

        Raises:
            jwt.ExpiredSignatureError: If token is expired
            jwt.InvalidTokenError: If token is invalid
        """
        payload = self.validate_token(token)

        if payload.get('token_type') != 'access':
            raise jwt.InvalidTokenError("Invalid token type for access token")

        return payload

    def validate_refresh_token(self, token: str) -> Dict[str, Any]:
        """
        Validate a refresh token specifically.

        Args:
            token: Refresh token to validate

        Returns:
            Decoded token payload

        Raises:
            jwt.ExpiredSignatureError: If token is expired
            jwt.InvalidTokenError: If token is invalid
        """
        payload = self.validate_token(token)

        if payload.get('token_type') != 'refresh':
            raise jwt.InvalidTokenError("Invalid token type for refresh token")

        return payload

    def get_token_expiration(self, token: str) -> Optional[datetime]:
        """
        Get token expiration time.

        Args:
            token: JWT token

        Returns:
            Expiration datetime or None if token is invalid
        """
        try:
            payload = self.validate_token(token)
            return datetime.fromtimestamp(payload['exp'])
        except Exception:
            return None

    def is_token_expired(self, token: str) -> bool:
        """
        Check if token is expired.

        Args:
            token: JWT token

        Returns:
            True if token is expired, False otherwise
        """
        try:
            self.validate_token(token)
            return False
        except jwt.ExpiredSignatureError:
            return True
        except Exception:
            return True

    def refresh_tokens(self, refresh_token: str, user_id: int, username: str, roles: list, session_id: str) -> Dict[str, str]:
        """
        Refresh access and refresh tokens using a valid refresh token.

        Args:
            refresh_token: Current refresh token
            user_id: User ID
            username: Username
            roles: List of user roles
            session_id: Session ID

        Returns:
            Dictionary with new access_token and refresh_token

        Raises:
            jwt.InvalidTokenError: If refresh token is invalid
        """
        # Validate the refresh token
        payload = self.validate_refresh_token(refresh_token)

        # Generate new token pair with token rotation
        return self.generate_token_pair(user_id, username, roles, session_id)

    def get_token_hash(self, token: str) -> str:
        """
        Get SHA-256 hash of a token for storage.

        Args:
            token: JWT token

        Returns:
            SHA-256 hash of the token
        """
        import hashlib
        return hashlib.sha256(token.encode('utf-8')).hexdigest()

    def verify_token_hash(self, token: str, token_hash: str) -> bool:
        """
        Verify if a token matches its stored hash.

        Args:
            token: JWT token
            token_hash: Stored token hash

        Returns:
            True if token matches hash, False otherwise
        """
        return self.get_token_hash(token) == token_hash

    def get_token_info(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get token information without full validation.

        Args:
            token: JWT token

        Returns:
            Token information dictionary or None if invalid
        """
        try:
            # Decode without verification to get header and basic info
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={'verify_signature': False})

            return {
                'header': header,
                'payload': payload,
                'valid': self.is_token_valid(token)
            }
        except Exception:
            return None

    def is_token_valid(self, token: str) -> bool:
        """
        Check if token is valid (not expired and properly signed).

        Args:
            token: JWT token

        Returns:
            True if token is valid, False otherwise
        """
        try:
            self.validate_token(token)
            return True
        except Exception:
            return False