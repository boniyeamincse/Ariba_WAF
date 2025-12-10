"""
Authentication API Module

Provides REST API endpoints for authentication functionality.
"""

import logging
from typing import Dict, Any, Optional, Tuple
from flask import Blueprint, request, jsonify, make_response
from werkzeug.security import safe_str_cmp
from .auth_service import auth_service
from .models import User
from config_manager import config_manager
from rate_limiter import rate_limiter
from ip_filter import ip_filter
from logging_module import logging_module

# Create authentication blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Initialize logger
logger = logging.getLogger('auth.api')

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    User login endpoint.

    Accepts:
    - JSON: {'username': str, 'password': str}
    - Form data: username, password

    Returns:
    - 200: Success with tokens
    - 400: Bad request
    - 401: Unauthorized
    - 429: Too many requests
    - 403: Forbidden (IP blocked)
    """
    try:
        # Get client information
        ip_address = request.remote_addr
        user_agent = request.user_agent.string

        # Check IP reputation
        ip_status = ip_filter.check_ip_reputation(ip_address)
        if not ip_status['allowed']:
            logger.warning(f"Login attempt blocked from IP {ip_address} due to reputation: {ip_status['reputation']}")
            return make_response(jsonify({
                'error': 'access_denied',
                'message': 'Access denied due to security policies'
            }), 403)

        # Check rate limiting
        rate_limit_key = f"auth_login_{ip_address}"
        if not rate_limiter.check_rate_limit(rate_limit_key, limit=5, window=300):
            logger.warning(f"Rate limit exceeded for login from IP {ip_address}")
            return make_response(jsonify({
                'error': 'rate_limit_exceeded',
                'message': 'Too many login attempts. Please try again later.'
            }), 429)

        # Get credentials
        data = request.get_json(silent=True) or request.form.to_dict()

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            logger.warning(f"Login attempt with missing credentials from IP {ip_address}")
            return make_response(jsonify({
                'error': 'invalid_request',
                'message': 'Username and password are required'
            }), 400)

        # Attempt login
        result = auth_service.login(username, password, ip_address, user_agent)

        if not result:
            logger.warning(f"Failed login attempt for username: {username} from IP {ip_address}")
            return make_response(jsonify({
                'error': 'invalid_credentials',
                'message': 'Invalid username or password'
            }), 401)

        # Create response
        response_data = {
            'success': True,
            'message': 'Login successful',
            'tokens': result['tokens'],
            'user': {
                'id': result['user']['id'],
                'username': result['user']['username'],
                'email': result['user']['email'],
                'roles': result['user']['roles'],
                'first_name': result['user'].get('first_name'),
                'last_name': result['user'].get('last_name')
            },
            'session': {
                'id': result['session']['id'],
                'expires_at': result['session']['expires_at']
            }
        }

        logger.info(f"Successful login for username: {username} from IP {ip_address}")
        return jsonify(response_data)

    except Exception as e:
        logger.error(f"Login endpoint error: {str(e)}", exc_info=True)
        return make_response(jsonify({
            'error': 'server_error',
            'message': 'An unexpected error occurred'
        }), 500)

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    User logout endpoint.

    Accepts:
    - JSON: {'access_token': str, 'refresh_token': str}
    - Form data: access_token, refresh_token
    - Authorization header: Bearer <access_token>

    Returns:
    - 200: Success
    - 400: Bad request
    - 401: Unauthorized
    - 500: Server error
    """
    try:
        # Get client information
        ip_address = request.remote_addr
        user_agent = request.user_agent.string

        # Get tokens from request
        auth_header = request.headers.get('Authorization')
        data = request.get_json(silent=True) or request.form.to_dict()

        access_token = None
        refresh_token = None

        # Try to get access token from Authorization header
        if auth_header and auth_header.startswith('Bearer '):
            access_token = auth_header[7:].strip()

        # Get tokens from request body
        if not access_token:
            access_token = data.get('access_token')
        refresh_token = data.get('refresh_token')

        if not access_token:
            logger.warning(f"Logout attempt with missing access token from IP {ip_address}")
            return make_response(jsonify({
                'error': 'invalid_request',
                'message': 'Access token is required'
            }), 400)

        # Validate access token to get user info
        session_info = auth_service.validate_session(access_token)
        if not session_info:
            logger.warning(f"Logout attempt with invalid access token from IP {ip_address}")
            return make_response(jsonify({
                'error': 'invalid_token',
                'message': 'Invalid access token'
            }), 401)

        # Attempt logout
        success = auth_service.logout(access_token, refresh_token or '')

        if not success:
            logger.warning(f"Logout failed for user {session_info['username']} from IP {ip_address}")
            return make_response(jsonify({
                'error': 'logout_failed',
                'message': 'Logout failed'
            }), 500)

        logger.info(f"Successful logout for user {session_info['username']} from IP {ip_address}")
        return jsonify({
            'success': True,
            'message': 'Logout successful'
        })

    except Exception as e:
        logger.error(f"Logout endpoint error: {str(e)}", exc_info=True)
        return make_response(jsonify({
            'error': 'server_error',
            'message': 'An unexpected error occurred'
        }), 500)

@auth_bp.route('/refresh', methods=['POST'])
def refresh():
    """
    Token refresh endpoint.

    Accepts:
    - JSON: {'refresh_token': str}
    - Form data: refresh_token

    Returns:
    - 200: Success with new tokens
    - 400: Bad request
    - 401: Unauthorized
    - 429: Too many requests
    - 500: Server error
    """
    try:
        # Get client information
        ip_address = request.remote_addr
        user_agent = request.user_agent.string

        # Check rate limiting
        data = request.get_json(silent=True) or request.form.to_dict()
        refresh_token = data.get('refresh_token')

        if not refresh_token:
            logger.warning(f"Token refresh attempt with missing refresh token from IP {ip_address}")
            return make_response(jsonify({
                'error': 'invalid_request',
                'message': 'Refresh token is required'
            }), 400)

        # Check rate limiting for token refresh
        token_info = auth_service.token_service.get_token_info(refresh_token)
        if token_info and token_info.get('valid'):
            user_id = token_info['payload'].get('sub')
            rate_limit_key = f"auth_refresh_{user_id}"
            if not rate_limiter.check_rate_limit(rate_limit_key, limit=10, window=60):
                logger.warning(f"Rate limit exceeded for token refresh from IP {ip_address}")
                return make_response(jsonify({
                    'error': 'rate_limit_exceeded',
                    'message': 'Too many refresh attempts. Please try again later.'
                }), 429)

        # Attempt token refresh
        result = auth_service.refresh_tokens(refresh_token, ip_address, user_agent)

        if not result:
            logger.warning(f"Token refresh failed from IP {ip_address}")
            return make_response(jsonify({
                'error': 'invalid_token',
                'message': 'Invalid or expired refresh token'
            }), 401)

        logger.info(f"Token refresh successful for user {result['session']['id']} from IP {ip_address}")
        return jsonify({
            'success': True,
            'message': 'Token refresh successful',
            'tokens': result['tokens'],
            'session': {
                'id': result['session']['id'],
                'expires_at': result['session']['expires_at']
            }
        })

    except Exception as e:
        logger.error(f"Token refresh endpoint error: {str(e)}", exc_info=True)
        return make_response(jsonify({
            'error': 'server_error',
            'message': 'An unexpected error occurred'
        }), 500)

@auth_bp.route('/status', methods=['GET'])
def status():
    """
    Session status endpoint.

    Accepts:
    - Authorization header: Bearer <access_token>

    Returns:
    - 200: Session status
    - 401: Unauthorized
    - 500: Server error
    """
    try:
        # Get access token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logger.warning(f"Session status check with missing authorization header from IP {request.remote_addr}")
            return make_response(jsonify({
                'error': 'unauthorized',
                'message': 'Authorization token is required'
            }), 401)

        access_token = auth_header[7:].strip()

        # Validate session
        session_status = auth_service.get_session_status(access_token)

        if not session_status['valid']:
            logger.warning(f"Session status check with invalid token from IP {request.remote_addr}")
            return make_response(jsonify({
                'error': 'invalid_session',
                'message': 'Invalid or expired session'
            }), 401)

        logger.info(f"Session status check for user {session_status['username']} from IP {request.remote_addr}")
        return jsonify({
            'success': True,
            'valid': True,
            'user': {
                'id': session_status['user_id'],
                'username': session_status['username'],
                'roles': session_status['roles']
            },
            'session': {
                'id': session_status['session_id'],
                'token_payload': session_status['token_payload']
            }
        })

    except Exception as e:
        logger.error(f"Session status endpoint error: {str(e)}", exc_info=True)
        return make_response(jsonify({
            'error': 'server_error',
            'message': 'An unexpected error occurred'
        }), 500)

@auth_bp.route('/password/strength', methods=['POST'])
def check_password_strength():
    """
    Password strength check endpoint.

    Accepts:
    - JSON: {'password': str}
    - Form data: password

    Returns:
    - 200: Password strength analysis
    - 400: Bad request
    - 500: Server error
    """
    try:
        data = request.get_json(silent=True) or request.form.to_dict()
        password = data.get('password')

        if not password:
            logger.warning(f"Password strength check with missing password from IP {request.remote_addr}")
            return make_response(jsonify({
                'error': 'invalid_request',
                'message': 'Password is required'
            }), 400)

        # Check password strength
        strength_result = auth_service.validate_password_strength(password)

        logger.info(f"Password strength check from IP {request.remote_addr}")
        return jsonify({
            'success': True,
            'valid': strength_result['valid'],
            'score': strength_result['score'],
            'strength': strength_result['strength'],
            'errors': strength_result['errors'],
            'requirements': strength_result['requirements'],
            'details': {
                'has_uppercase': strength_result['has_uppercase'],
                'has_lowercase': strength_result['has_lowercase'],
                'has_digits': strength_result['has_digits'],
                'has_special_chars': strength_result['has_special_chars'],
                'length': strength_result['length'],
                'entropy': strength_result['entropy']
            }
        })

    except Exception as e:
        logger.error(f"Password strength endpoint error: {str(e)}", exc_info=True)
        return make_response(jsonify({
            'error': 'server_error',
            'message': 'An unexpected error occurred'
        }), 500)

def register_auth_blueprint(app):
    """
    Register authentication blueprint with Flask app.

    Args:
        app: Flask application instance
    """
    app.register_blueprint(auth_bp)
    logger.info("Authentication blueprint registered")

def create_auth_middleware(app):
    """
    Create authentication middleware for Flask app.

    Args:
        app: Flask application instance

    Returns:
        Function to use as before_request middleware
    """
    def auth_middleware():
        # Skip authentication for auth endpoints and public routes
        if request.path.startswith('/api/auth'):
            return

        # Check for Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return make_response(jsonify({
                'error': 'unauthorized',
                'message': 'Authentication required'
            }), 401)

        access_token = auth_header[7:].strip()

        # Validate session
        session_status = auth_service.get_session_status(access_token)
        if not session_status['valid']:
            return make_response(jsonify({
                'error': 'invalid_session',
                'message': 'Invalid or expired session'
            }), 401)

        # Store user info in request context
        request.user = {
            'id': session_status['user_id'],
            'username': session_status['username'],
            'roles': session_status['roles']
        }

    return auth_middleware