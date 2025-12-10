"""
Auth Service Module

Main authentication service that coordinates all authentication operations.
"""

import logging
from typing import Dict, Any, Optional, Tuple
from .password_service import PasswordService
from .session_service import SessionService
from .token_service import TokenService
from config_manager import config_manager
from rate_limiter import rate_limiter
from ip_filter import ip_filter
from logging_module import logging_module

class AuthService:
    """
    Main authentication service that handles user authentication, session management,
    and integration with other WAF components.
    """

    def __init__(self):
        self.logger = logging.getLogger('auth.auth_service')
        self.config = config_manager.get_config('authentication')

        # Initialize services
        self.password_service = PasswordService()
        self.session_service = SessionService()
        self.token_service = TokenService()

        # Integration with existing WAF components
        self.rate_limiter = rate_limiter
        self.ip_filter = ip_filter
        self.logging_module = logging_module

        # Authentication settings
        self.max_failed_attempts = self.config.get('max_failed_attempts', 5)
        self.account_lockout_duration = self.config.get('account_lockout_duration_minutes', 30)

        self.logger.info("AuthService initialized")

    def login(self, username: str, password: str, ip_address: str, user_agent: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate user and create session.

        Args:
            username: Username or email
            password: Password
            ip_address: Client IP address
            user_agent: Client user agent

        Returns:
            Dictionary with tokens and user info if successful, None otherwise
        """
        # Check IP reputation
        ip_status = self.ip_filter.check_ip_reputation(ip_address)
        if not ip_status['allowed']:
            self._log_auth_event(
                username=username,
                event_type='login_attempt',
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={'reason': 'ip_blocked', 'ip_reputation': ip_status['reputation']}
            )
            return None

        # Check rate limiting
        rate_limit_key = f"auth_login_{ip_address}"
        if not self.rate_limiter.check_rate_limit(rate_limit_key, limit=5, window=300):
            self._log_auth_event(
                username=username,
                event_type='login_attempt',
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={'reason': 'rate_limited'}
            )
            return None

        # In a real implementation, we would look up the user in the database
        # For now, we'll simulate a user lookup
        user = self._get_user_by_username_or_email(username)
        if not user:
            self._log_auth_event(
                username=username,
                event_type='login_attempt',
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={'reason': 'user_not_found'}
            )
            return None

        # Check if account is locked
        if user.get('is_locked', False):
            self._log_auth_event(
                username=username,
                event_type='login_attempt',
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={'reason': 'account_locked'}
            )
            return None

        # Verify password
        if not self.password_service.verify_password(password, user['password_hash']):
            # Increment failed attempts
            failed_attempts = user.get('failed_login_attempts', 0) + 1

            # Check if account should be locked
            if failed_attempts >= self.max_failed_attempts:
                self._lock_user_account(user['id'])
                self._log_auth_event(
                    username=username,
                    event_type='account_locked',
                    success=False,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={'failed_attempts': failed_attempts}
                )
            else:
                self._log_auth_event(
                    username=username,
                    event_type='login_attempt',
                    success=False,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={'reason': 'invalid_password', 'failed_attempts': failed_attempts}
                )

            return None

        # Check if user can create new session
        if not self.session_service.can_create_new_session(user['id']):
            self._log_auth_event(
                username=username,
                event_type='login_attempt',
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={'reason': 'max_sessions_reached'}
            )
            return None

        # Reset failed attempts on successful login
        self._reset_failed_attempts(user['id'])

        # Create session
        session_result = self.session_service.create_session(
            user_id=user['id'],
            username=user['username'],
            roles=user.get('roles', ['viewer']),
            ip_address=ip_address,
            user_agent=user_agent
        )

        # Log successful login
        self._log_auth_event(
            username=username,
            event_type='login_success',
            success=True,
            ip_address=ip_address,
            user_agent=user_agent,
            details={'session_id': session_result['session']['session_id']}
        )

        return {
            'tokens': session_result['tokens'],
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'roles': user.get('roles', ['viewer']),
                'first_name': user.get('first_name'),
                'last_name': user.get('last_name')
            },
            'session': {
                'id': session_result['session']['session_id'],
                'expires_at': session_result['session']['access_token_expires_at'].isoformat(),
                'ip_address': ip_address
            }
        }

    def logout(self, access_token: str, refresh_token: str) -> bool:
        """
        Logout user and revoke session.

        Args:
            access_token: Access token
            refresh_token: Refresh token

        Returns:
            True if logout was successful, False otherwise
        """
        try:
            # Validate access token to get session info
            token_payload = self.token_service.validate_access_token(access_token)
            session_id = token_payload.get('session_id')
            user_id = token_payload.get('sub')
            username = token_payload.get('username')

            # Revoke session
            success = self.session_service.revoke_session(
                session_id=session_id,
                revoked_by=user_id,
                reason='user_logout'
            )

            if success:
                self._log_auth_event(
                    username=username,
                    event_type='logout',
                    success=True,
                    details={'session_id': session_id}
                )

            return success

        except Exception as e:
            self.logger.error(f"Logout failed: {str(e)}")
            return False

    def refresh_tokens(self, refresh_token: str, ip_address: str, user_agent: str) -> Optional[Dict[str, Any]]:
        """
        Refresh access and refresh tokens.

        Args:
            refresh_token: Refresh token
            ip_address: Client IP address
            user_agent: Client user agent

        Returns:
            Dictionary with new tokens if successful, None otherwise
        """
        # Check rate limiting for token refresh
        token_payload = self.token_service.get_token_info(refresh_token)
        if token_payload and token_payload.get('valid'):
            user_id = token_payload['payload'].get('sub')
            rate_limit_key = f"auth_refresh_{user_id}"
            if not self.rate_limiter.check_rate_limit(rate_limit_key, limit=10, window=60):
                self._log_auth_event(
                    username=token_payload['payload'].get('username'),
                    event_type='token_refresh_attempt',
                    success=False,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={'reason': 'rate_limited'}
                )
                return None

        # Refresh session
        session_result = self.session_service.refresh_session(refresh_token, ip_address, user_agent)

        if session_result:
            user_id = session_result['session']['user_id']
            username = session_result['session']['username']

            self._log_auth_event(
                username=username,
                event_type='token_refresh',
                success=True,
                ip_address=ip_address,
                user_agent=user_agent,
                details={'session_id': session_result['session']['session_id']}
            )

            return {
                'tokens': session_result['tokens'],
                'session': {
                    'id': session_result['session']['session_id'],
                    'expires_at': session_result['session']['access_token_expires_at'].isoformat()
                }
            }

        return None

    def validate_session(self, access_token: str) -> Optional[Dict[str, Any]]:
        """
        Validate user session.

        Args:
            access_token: Access token

        Returns:
            Session information if valid, None otherwise
        """
        return self.session_service.validate_session(access_token)

    def get_session_status(self, access_token: str) -> Dict[str, Any]:
        """
        Get session status information.

        Args:
            access_token: Access token

        Returns:
            Dictionary with session status
        """
        session_info = self.session_service.validate_session(access_token)

        if session_info:
            return {
                'valid': True,
                'user_id': session_info['user_id'],
                'username': session_info['username'],
                'roles': session_info['roles'],
                'session_id': session_info['session_id'],
                'token_payload': session_info['token_payload']
            }
        else:
            return {
                'valid': False,
                'error': 'invalid_session'
            }

    def _get_user_by_username_or_email(self, username_or_email: str) -> Optional[Dict[str, Any]]:
        """
        Get user by username or email (simulated for now).

        Args:
            username_or_email: Username or email

        Returns:
            User dictionary if found, None otherwise
        """
        # In a real implementation, this would query the database
        # For now, we'll return a mock user for testing
        if username_or_email in ['admin', 'admin@example.com']:
            return {
                'id': 1,
                'username': 'admin',
                'email': 'admin@example.com',
                'password_hash': self.password_service.hash_password('admin123!'),
                'roles': ['super_admin'],
                'first_name': 'Admin',
                'last_name': 'User',
                'is_active': True,
                'is_locked': False,
                'failed_login_attempts': 0
            }
        elif username_or_email in ['user', 'user@example.com']:
            return {
                'id': 2,
                'username': 'user',
                'email': 'user@example.com',
                'password_hash': self.password_service.hash_password('user123!'),
                'roles': ['viewer'],
                'first_name': 'Regular',
                'last_name': 'User',
                'is_active': True,
                'is_locked': False,
                'failed_login_attempts': 0
            }
        else:
            return None

    def _lock_user_account(self, user_id: int) -> bool:
        """
        Lock user account (simulated for now).

        Args:
            user_id: User ID

        Returns:
            True if account was locked, False otherwise
        """
        # In a real implementation, this would update the database
        self.logger.warning(f"Locked user account {user_id}")
        return True

    def _reset_failed_attempts(self, user_id: int) -> bool:
        """
        Reset failed login attempts for user (simulated for now).

        Args:
            user_id: User ID

        Returns:
            True if reset was successful, False otherwise
        """
        # In a real implementation, this would update the database
        self.logger.debug(f"Reset failed attempts for user {user_id}")
        return True

    def _log_auth_event(self, username: str, event_type: str, success: bool,
                       ip_address: str = None, user_agent: str = None,
                       details: Dict[str, Any] = None) -> None:
        """
        Log authentication event.

        Args:
            username: Username
            event_type: Type of authentication event
            success: Whether the event was successful
            ip_address: Client IP address (optional)
            user_agent: Client user agent (optional)
            details: Additional event details (optional)
        """
        log_data = {
            'username': username,
            'event_type': event_type,
            'success': success,
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': ip_address,
            'user_agent': user_agent,
            'details': details or {}
        }

        # Log to logging module
        self.logging_module.log_event(
            'authentication',
            event_type,
            log_data,
            severity='info' if success else 'warning'
        )

        # Log to console
        log_level = logging.INFO if success else logging.WARNING
        self.logger.log(
            log_level,
            f"Authentication event - {event_type} - username: {username} - success: {success}",
            extra={'auth_event': log_data}
        )

    def validate_password_strength(self, password: str) -> Dict[str, Any]:
        """
        Validate password strength.

        Args:
            password: Password to validate

        Returns:
            Password validation result
        """
        return self.password_service.validate_password_strength(password)

    def hash_password(self, password: str) -> str:
        """
        Hash password.

        Args:
            password: Password to hash

        Returns:
            Hashed password
        """
        return self.password_service.hash_password(password)

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify password.

        Args:
            password: Password to verify
            hashed_password: Hashed password to verify against

        Returns:
            True if password matches, False otherwise
        """
        return self.password_service.verify_password(password, hashed_password)

    def get_user_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a user.

        Args:
            user_id: User ID

        Returns:
            List of active sessions
        """
        return self.session_service.get_active_sessions(user_id)

    def revoke_user_session(self, user_id: int, session_id: str) -> bool:
        """
        Revoke a specific session for a user.

        Args:
            user_id: User ID
            session_id: Session ID

        Returns:
            True if session was revoked, False otherwise
        """
        return self.session_service.revoke_session(session_id, revoked_by=user_id, reason='admin_revocation')

    def revoke_all_user_sessions(self, user_id: int) -> int:
        """
        Revoke all sessions for a user.

        Args:
            user_id: User ID

        Returns:
            Number of sessions revoked
        """
        return self.session_service.revoke_all_user_sessions(user_id, revoked_by=user_id, reason='admin_revocation')