"""
Password Service Module

Provides secure password hashing and verification using bcrypt.
"""

import bcrypt
import re
import logging
from typing import Optional, Dict, Any
from config_manager import config_manager

class PasswordService:
    """
    Password service for secure password hashing and verification.
    """

    def __init__(self):
        self.logger = logging.getLogger('auth.password_service')
        self.config = config_manager.get_config('authentication')

        # Initialize bcrypt work factor from config or use default
        self.bcrypt_rounds = self.config.get('bcrypt_rounds', 12)

        # Password strength requirements
        self.min_length = self.config.get('min_password_length', 12)
        self.require_uppercase = self.config.get('require_uppercase', True)
        self.require_lowercase = self.config.get('require_lowercase', True)
        self.require_digits = self.config.get('require_digits', True)
        self.require_special = self.config.get('require_special', True)
        self.max_length = self.config.get('max_password_length', 128)

    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt with configurable work factor.

        Args:
            password: Plain text password to hash

        Returns:
            Hashed password string

        Raises:
            ValueError: If password is empty or too long
        """
        if not password:
            raise ValueError("Password cannot be empty")

        if len(password) > self.max_length:
            raise ValueError(f"Password exceeds maximum length of {self.max_length} characters")

        # Generate salt and hash password
        salt = bcrypt.gensalt(rounds=self.bcrypt_rounds)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

        return hashed.decode('utf-8')

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify password against bcrypt hash.

        Args:
            password: Plain text password to verify
            hashed_password: Stored bcrypt hash

        Returns:
            True if password matches hash, False otherwise

        Raises:
            ValueError: If password is empty
        """
        if not password:
            raise ValueError("Password cannot be empty")

        if not hashed_password:
            self.logger.warning("Empty password hash provided for verification")
            return False

        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        except (ValueError, TypeError) as e:
            self.logger.error(f"Password verification error: {str(e)}")
            return False

    def validate_password_strength(self, password: str) -> Dict[str, Any]:
        """
        Validate password strength against configured requirements.

        Args:
            password: Password to validate

        Returns:
            Dictionary with validation results and strength score
        """
        if not password:
            return {
                'valid': False,
                'score': 0,
                'errors': ['Password cannot be empty'],
                'requirements': self._get_password_requirements()
            }

        if len(password) < self.min_length:
            return {
                'valid': False,
                'score': 0,
                'errors': [f'Password must be at least {self.min_length} characters long'],
                'requirements': self._get_password_requirements()
            }

        if len(password) > self.max_length:
            return {
                'valid': False,
                'score': 0,
                'errors': [f'Password must be no more than {self.max_length} characters long'],
                'requirements': self._get_password_requirements()
            }

        # Check character requirements
        errors = []
        score = 0

        # Length score (0-20 points)
        length_score = min(20, (len(password) - 8) * 2)  # 8 chars = 0, 13 chars = 10, 18 chars = 20
        score += length_score

        # Character diversity score (0-30 points)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^A-Za-z0-9]', password))

        diversity_score = 0
        if has_upper: diversity_score += 5
        if has_lower: diversity_score += 5
        if has_digit: diversity_score += 10
        if has_special: diversity_score += 10

        score += diversity_score

        # Check requirements
        if self.require_uppercase and not has_upper:
            errors.append('Password must contain at least one uppercase letter')
        if self.require_lowercase and not has_lower:
            errors.append('Password must contain at least one lowercase letter')
        if self.require_digits and not has_digit:
            errors.append('Password must contain at least one digit')
        if self.require_special and not has_special:
            errors.append('Password must contain at least one special character')

        # Entropy score (0-30 points)
        entropy = self._calculate_entropy(password)
        entropy_score = min(30, entropy // 2)  # Cap at 30 points
        score += entropy_score

        # Bonus for longer passwords (0-20 points)
        bonus_score = min(20, (len(password) - 12) * 2)  # 12 chars = 0, 17 chars = 10, 22 chars = 20
        score += bonus_score

        # Cap total score at 100
        score = min(100, score)

        # Determine strength level
        if score >= 80:
            strength = 'very_strong'
        elif score >= 60:
            strength = 'strong'
        elif score >= 40:
            strength = 'moderate'
        elif score >= 20:
            strength = 'weak'
        else:
            strength = 'very_weak'

        return {
            'valid': len(errors) == 0,
            'score': score,
            'strength': strength,
            'errors': errors,
            'requirements': self._get_password_requirements(),
            'has_uppercase': has_upper,
            'has_lowercase': has_lower,
            'has_digits': has_digit,
            'has_special_chars': has_special,
            'length': len(password),
            'entropy': entropy
        }

    def _calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy in bits.

        Args:
            password: Password to calculate entropy for

        Returns:
            Entropy value in bits
        """
        if not password:
            return 0.0

        # Character pool sizes
        pool_size = 0
        if re.search(r'[a-z]', password):
            pool_size += 26  # lowercase
        if re.search(r'[A-Z]', password):
            pool_size += 26  # uppercase
        if re.search(r'[0-9]', password):
            pool_size += 10  # digits
        if re.search(r'[^A-Za-z0-9]', password):
            pool_size += 32  # common special chars

        if pool_size == 0:
            return 0.0

        # Calculate entropy: log2(pool_size^length)
        import math
        return math.log2(pool_size ** len(password))

    def _get_password_requirements(self) -> Dict[str, Any]:
        """
        Get current password requirements.

        Returns:
            Dictionary of password requirements
        """
        return {
            'min_length': self.min_length,
            'max_length': self.max_length,
            'require_uppercase': self.require_uppercase,
            'require_lowercase': self.require_lowercase,
            'require_digits': self.require_digits,
            'require_special': self.require_special,
            'bcrypt_rounds': self.bcrypt_rounds
        }

    def needs_rehash(self, hashed_password: str) -> bool:
        """
        Check if a password hash needs to be rehashed with current settings.

        Args:
            hashed_password: Existing password hash

        Returns:
            True if hash should be rehashed, False otherwise
        """
        if not hashed_password:
            return False

        try:
            # Extract rounds from existing hash
            # bcrypt hash format: $2b$rounds$salt
            parts = hashed_password.split('$')
            if len(parts) >= 3:
                current_rounds = int(parts[2])
                return current_rounds < self.bcrypt_rounds
        except (ValueError, IndexError):
            pass

        return False