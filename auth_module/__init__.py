"""
Ariba WAF Authentication Module

This module provides comprehensive authentication services including:
- Password hashing and verification
- Session management
- JWT token handling
- User authentication
- Security integration

Core Components:
- auth_service: Main authentication service
- password_service: Password hashing and validation
- session_service: Session management
- token_service: JWT token generation and validation
- models: Database models for authentication
- api: REST API endpoints for authentication
"""

from .auth_service import AuthService
from .password_service import PasswordService
from .session_service import SessionService
from .token_service import TokenService
from .models import (
    User, Session, AuthenticationLog, PasswordResetToken,
    Role, Permission, RolePermission, UserRole
)
from .api import auth_bp, register_auth_blueprint, create_auth_middleware

# Initialize services
auth_service = AuthService()
password_service = PasswordService()
session_service = SessionService()
token_service = TokenService()

__all__ = [
    'AuthService',
    'PasswordService',
    'SessionService',
    'TokenService',
    'User', 'Session', 'AuthenticationLog', 'PasswordResetToken',
    'Role', 'Permission', 'RolePermission', 'UserRole',
    'auth_bp', 'register_auth_blueprint', 'create_auth_middleware',
    'auth_service',
    'password_service',
    'session_service',
    'token_service'
]