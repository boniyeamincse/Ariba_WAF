"""
Database Models for Authentication System

This module defines the database models for the authentication system.
These models correspond to the tables defined in the architecture.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
from enum import Enum

class UserRole(Enum):
    """User role enumeration."""
    SUPER_ADMIN = 'super_admin'
    ADMIN = 'admin'
    VIEWER = 'viewer'

class User:
    """
    User model representing the users table.
    """

    def __init__(self,
                 id: Optional[int] = None,
                 username: Optional[str] = None,
                 email: Optional[str] = None,
                 password_hash: Optional[str] = None,
                 role: Optional[UserRole] = None,
                 first_name: Optional[str] = None,
                 last_name: Optional[str] = None,
                 is_active: bool = True,
                 is_locked: bool = False,
                 failed_login_attempts: int = 0,
                 last_login: Optional[datetime] = None,
                 created_at: Optional[datetime] = None,
                 updated_at: Optional[datetime] = None,
                 created_by: Optional[int] = None,
                 updated_by: Optional[int] = None):
        """
        Initialize User model.

        Args:
            id: User ID
            username: Username
            email: Email address
            password_hash: Hashed password
            role: User role
            first_name: First name
            last_name: Last name
            is_active: Whether user is active
            is_locked: Whether user is locked
            failed_login_attempts: Number of failed login attempts
            last_login: Last login timestamp
            created_at: Creation timestamp
            updated_at: Last update timestamp
            created_by: User ID who created this user
            updated_by: User ID who last updated this user
        """
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.first_name = first_name
        self.last_name = last_name
        self.is_active = is_active
        self.is_locked = is_locked
        self.failed_login_attempts = failed_login_attempts
        self.last_login = last_login
        self.created_at = created_at or datetime.utcnow()
        self.updated_at = updated_at or datetime.utcnow()
        self.created_by = created_by
        self.updated_by = updated_by

    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'password_hash': self.password_hash,
            'role': self.role.value if self.role else None,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_active': self.is_active,
            'is_locked': self.is_locked,
            'failed_login_attempts': self.failed_login_attempts,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'created_by': self.created_by,
            'updated_by': self.updated_by
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create user from dictionary."""
        role = None
        if data.get('role'):
            try:
                role = UserRole(data['role'])
            except ValueError:
                pass

        return cls(
            id=data.get('id'),
            username=data.get('username'),
            email=data.get('email'),
            password_hash=data.get('password_hash'),
            role=role,
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            is_active=data.get('is_active', True),
            is_locked=data.get('is_locked', False),
            failed_login_attempts=data.get('failed_login_attempts', 0),
            last_login=datetime.fromisoformat(data['last_login']) if data.get('last_login') else None,
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            updated_at=datetime.fromisoformat(data['updated_at']) if data.get('updated_at') else None,
            created_by=data.get('created_by'),
            updated_by=data.get('updated_by')
        )

class Session:
    """
    Session model representing the sessions table.
    """

    def __init__(self,
                 session_id: Optional[str] = None,
                 user_id: Optional[int] = None,
                 access_token_hash: Optional[str] = None,
                 refresh_token_hash: Optional[str] = None,
                 access_token_expires_at: Optional[datetime] = None,
                 refresh_token_expires_at: Optional[datetime] = None,
                 ip_address: Optional[str] = None,
                 user_agent: Optional[str] = None,
                 is_active: bool = True,
                 created_at: Optional[datetime] = None,
                 last_used_at: Optional[datetime] = None,
                 revoked_at: Optional[datetime] = None,
                 revoked_by: Optional[int] = None,
                 revocation_reason: Optional[str] = None):
        """
        Initialize Session model.

        Args:
            session_id: Session ID (UUID)
            user_id: User ID
            access_token_hash: Hash of access token
            refresh_token_hash: Hash of refresh token
            access_token_expires_at: Access token expiration
            refresh_token_expires_at: Refresh token expiration
            ip_address: Client IP address
            user_agent: Client user agent
            is_active: Whether session is active
            created_at: Creation timestamp
            last_used_at: Last used timestamp
            revoked_at: Revocation timestamp
            revoked_by: User ID who revoked session
            revocation_reason: Reason for revocation
        """
        self.session_id = session_id or str(uuid.uuid4())
        self.user_id = user_id
        self.access_token_hash = access_token_hash
        self.refresh_token_hash = refresh_token_hash
        self.access_token_expires_at = access_token_expires_at
        self.refresh_token_expires_at = refresh_token_expires_at
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.is_active = is_active
        self.created_at = created_at or datetime.utcnow()
        self.last_used_at = last_used_at
        self.revoked_at = revoked_at
        self.revoked_by = revoked_by
        self.revocation_reason = revocation_reason

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'access_token_hash': self.access_token_hash,
            'refresh_token_hash': self.refresh_token_hash,
            'access_token_expires_at': self.access_token_expires_at.isoformat() if self.access_token_expires_at else None,
            'refresh_token_expires_at': self.refresh_token_expires_at.isoformat() if self.refresh_token_expires_at else None,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
            'revoked_by': self.revoked_by,
            'revocation_reason': self.revocation_reason
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Session':
        """Create session from dictionary."""
        return cls(
            session_id=data.get('session_id'),
            user_id=data.get('user_id'),
            access_token_hash=data.get('access_token_hash'),
            refresh_token_hash=data.get('refresh_token_hash'),
            access_token_expires_at=datetime.fromisoformat(data['access_token_expires_at']) if data.get('access_token_expires_at') else None,
            refresh_token_expires_at=datetime.fromisoformat(data['refresh_token_expires_at']) if data.get('refresh_token_expires_at') else None,
            ip_address=data.get('ip_address'),
            user_agent=data.get('user_agent'),
            is_active=data.get('is_active', True),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            last_used_at=datetime.fromisoformat(data['last_used_at']) if data.get('last_used_at') else None,
            revoked_at=datetime.fromisoformat(data['revoked_at']) if data.get('revoked_at') else None,
            revoked_by=data.get('revoked_by'),
            revocation_reason=data.get('revocation_reason')
        )

    def is_expired(self) -> bool:
        """Check if session is expired."""
        if self.access_token_expires_at and self.access_token_expires_at < datetime.utcnow():
            return True
        return False

    def is_refresh_token_expired(self) -> bool:
        """Check if refresh token is expired."""
        if self.refresh_token_expires_at and self.refresh_token_expires_at < datetime.utcnow():
            return True
        return False

class AuthenticationLog:
    """
    Authentication log model representing the authentication_logs table.
    """

    def __init__(self,
                 log_id: Optional[int] = None,
                 user_id: Optional[int] = None,
                 username: Optional[str] = None,
                 event_type: Optional[str] = None,
                 event_timestamp: Optional[datetime] = None,
                 ip_address: Optional[str] = None,
                 user_agent: Optional[str] = None,
                 success: bool = False,
                 details: Optional[Dict[str, Any]] = None,
                 metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize AuthenticationLog model.

        Args:
            log_id: Log ID
            user_id: User ID
            username: Username
            event_type: Type of authentication event
            event_timestamp: Event timestamp
            ip_address: Client IP address
            user_agent: Client user agent
            success: Whether event was successful
            details: Additional event details
            metadata: Additional metadata
        """
        self.log_id = log_id
        self.user_id = user_id
        self.username = username
        self.event_type = event_type
        self.event_timestamp = event_timestamp or datetime.utcnow()
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.success = success
        self.details = details or {}
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert authentication log to dictionary."""
        return {
            'log_id': self.log_id,
            'user_id': self.user_id,
            'username': self.username,
            'event_type': self.event_type,
            'event_timestamp': self.event_timestamp.isoformat(),
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'success': self.success,
            'details': self.details,
            'metadata': self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuthenticationLog':
        """Create authentication log from dictionary."""
        return cls(
            log_id=data.get('log_id'),
            user_id=data.get('user_id'),
            username=data.get('username'),
            event_type=data.get('event_type'),
            event_timestamp=datetime.fromisoformat(data['event_timestamp']) if data.get('event_timestamp') else None,
            ip_address=data.get('ip_address'),
            user_agent=data.get('user_agent'),
            success=data.get('success', False),
            details=data.get('details', {}),
            metadata=data.get('metadata', {})
        )

class PasswordResetToken:
    """
    Password reset token model representing the password_reset_tokens table.
    """

    def __init__(self,
                 token_id: Optional[int] = None,
                 user_id: Optional[int] = None,
                 token_hash: Optional[str] = None,
                 expires_at: Optional[datetime] = None,
                 used: bool = False,
                 used_at: Optional[datetime] = None,
                 created_at: Optional[datetime] = None,
                 created_by: Optional[int] = None):
        """
        Initialize PasswordResetToken model.

        Args:
            token_id: Token ID
            user_id: User ID
            token_hash: Hash of reset token
            expires_at: Expiration timestamp
            used: Whether token has been used
            used_at: When token was used
            created_at: Creation timestamp
            created_by: User ID who created token
        """
        self.token_id = token_id
        self.user_id = user_id
        self.token_hash = token_hash
        self.expires_at = expires_at
        self.used = used
        self.used_at = used_at
        self.created_at = created_at or datetime.utcnow()
        self.created_by = created_by

    def to_dict(self) -> Dict[str, Any]:
        """Convert password reset token to dictionary."""
        return {
            'token_id': self.token_id,
            'user_id': self.user_id,
            'token_hash': self.token_hash,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'used': self.used,
            'used_at': self.used_at.isoformat() if self.used_at else None,
            'created_at': self.created_at.isoformat(),
            'created_by': self.created_by
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PasswordResetToken':
        """Create password reset token from dictionary."""
        return cls(
            token_id=data.get('token_id'),
            user_id=data.get('user_id'),
            token_hash=data.get('token_hash'),
            expires_at=datetime.fromisoformat(data['expires_at']) if data.get('expires_at') else None,
            used=data.get('used', False),
            used_at=datetime.fromisoformat(data['used_at']) if data.get('used_at') else None,
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            created_by=data.get('created_by')
        )

    def is_expired(self) -> bool:
        """Check if token is expired."""
        if self.expires_at and self.expires_at < datetime.utcnow():
            return True
        return False

class Role:
    """
    Role model representing the roles table.
    """

    def __init__(self,
                 role_id: Optional[int] = None,
                 role_name: Optional[str] = None,
                 description: Optional[str] = None,
                 is_system_role: bool = False,
                 created_at: Optional[datetime] = None,
                 updated_at: Optional[datetime] = None):
        """
        Initialize Role model.

        Args:
            role_id: Role ID
            role_name: Role name
            description: Role description
            is_system_role: Whether role is system role
            created_at: Creation timestamp
            updated_at: Last update timestamp
        """
        self.role_id = role_id
        self.role_name = role_name
        self.description = description
        self.is_system_role = is_system_role
        self.created_at = created_at or datetime.utcnow()
        self.updated_at = updated_at or datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert role to dictionary."""
        return {
            'role_id': self.role_id,
            'role_name': self.role_name,
            'description': self.description,
            'is_system_role': self.is_system_role,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Role':
        """Create role from dictionary."""
        return cls(
            role_id=data.get('role_id'),
            role_name=data.get('role_name'),
            description=data.get('description'),
            is_system_role=data.get('is_system_role', False),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            updated_at=datetime.fromisoformat(data['updated_at']) if data.get('updated_at') else None
        )

class Permission:
    """
    Permission model representing the permissions table.
    """

    def __init__(self,
                 permission_id: Optional[int] = None,
                 permission_name: Optional[str] = None,
                 description: Optional[str] = None,
                 category: Optional[str] = None,
                 created_at: Optional[datetime] = None,
                 updated_at: Optional[datetime] = None):
        """
        Initialize Permission model.

        Args:
            permission_id: Permission ID
            permission_name: Permission name
            description: Permission description
            category: Permission category
            created_at: Creation timestamp
            updated_at: Last update timestamp
        """
        self.permission_id = permission_id
        self.permission_name = permission_name
        self.description = description
        self.category = category
        self.created_at = created_at or datetime.utcnow()
        self.updated_at = updated_at or datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert permission to dictionary."""
        return {
            'permission_id': self.permission_id,
            'permission_name': self.permission_name,
            'description': self.description,
            'category': self.category,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Permission':
        """Create permission from dictionary."""
        return cls(
            permission_id=data.get('permission_id'),
            permission_name=data.get('permission_name'),
            description=data.get('description'),
            category=data.get('category'),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            updated_at=datetime.fromisoformat(data['updated_at']) if data.get('updated_at') else None
        )

class RolePermission:
    """
    Role-Permission mapping model representing the role_permissions table.
    """

    def __init__(self,
                 role_id: Optional[int] = None,
                 permission_id: Optional[int] = None,
                 created_at: Optional[datetime] = None,
                 created_by: Optional[int] = None):
        """
        Initialize RolePermission model.

        Args:
            role_id: Role ID
            permission_id: Permission ID
            created_at: Creation timestamp
            created_by: User ID who created mapping
        """
        self.role_id = role_id
        self.permission_id = permission_id
        self.created_at = created_at or datetime.utcnow()
        self.created_by = created_by

    def to_dict(self) -> Dict[str, Any]:
        """Convert role-permission mapping to dictionary."""
        return {
            'role_id': self.role_id,
            'permission_id': self.permission_id,
            'created_at': self.created_at.isoformat(),
            'created_by': self.created_by
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RolePermission':
        """Create role-permission mapping from dictionary."""
        return cls(
            role_id=data.get('role_id'),
            permission_id=data.get('permission_id'),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            created_by=data.get('created_by')
        )