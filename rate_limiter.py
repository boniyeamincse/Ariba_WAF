#!/usr/bin/env python3
"""
Ariba WAF Rate Limiter Module

A comprehensive rate limiting system that implements token bucket algorithm
for per-IP and per-endpoint rate limiting with Redis support for distributed environments.

Features:
- Token bucket algorithm implementation
- Per-IP and per-endpoint rate limiting
- Support for different HTTP methods (GET, POST, etc.)
- Configurable rate limits and burst capacity
- Redis integration for distributed rate limiting
- Comprehensive error handling and logging
- Integration with existing security engine
"""

import time
import hashlib
import logging
import threading
from typing import Dict, Any, Optional, Tuple, Union
from enum import Enum
import json
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None
from datetime import datetime, timedelta

# Try to import existing modules for integration
try:
    from logging_module import LoggingModule, LogLevel
    from security_engine import SecurityEngine
except ImportError:
    # Fallback for standalone testing
    class LoggingModule:
        def __init__(self, *args, **kwargs):
            pass

        def log_system_event(self, message, level="INFO"):
            print(f"[LOG] {message}")

        def log_error(self, message, exception=None):
            print(f"[ERROR] {message}")

    class SecurityEngine:
        pass

class RateLimitAction(Enum):
    """Rate limit actions"""
    ALLOW = "allow"
    BLOCK = "block"
    CHALLENGE = "challenge"

class RateLimitScope(Enum):
    """Rate limit scopes"""
    IP = "ip"
    ENDPOINT = "endpoint"
    IP_ENDPOINT = "ip_endpoint"
    GLOBAL = "global"

class TokenBucket:
    """
    Token Bucket Algorithm Implementation

    The token bucket algorithm is used for rate limiting. Tokens are added to the
    bucket at a fixed rate (refill rate). Each request consumes tokens from the bucket.
    When the bucket is empty, requests are rate limited.
    """

    def __init__(self, capacity: int, refill_rate: float, refill_interval: float = 1.0):
        """
        Initialize token bucket

        Args:
            capacity: Maximum number of tokens the bucket can hold (burst capacity)
            refill_rate: Number of tokens to add per refill interval
            refill_interval: Time interval in seconds for refilling tokens
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.refill_interval = refill_interval
        self.tokens = capacity
        self.last_refill_time = time.time()
        self.lock = threading.Lock()

    def _refill_tokens(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_refill_time

        if elapsed > 0:
            # Calculate how many tokens to add
            tokens_to_add = (elapsed / self.refill_interval) * self.refill_rate
            self.tokens = min(self.capacity, self.tokens + tokens_to_add)
            self.last_refill_time = now

    def consume(self, tokens: int = 1) -> bool:
        """
        Consume tokens from the bucket

        Args:
            tokens: Number of tokens to consume

        Returns:
            bool: True if tokens were consumed successfully, False if rate limited
        """
        with self.lock:
            self._refill_tokens()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def get_available_tokens(self) -> float:
        """Get current available tokens"""
        with self.lock:
            self._refill_tokens()
            return self.tokens

    def get_bucket_info(self) -> Dict[str, Union[float, int]]:
        """Get bucket information"""
        with self.lock:
            self._refill_tokens()
            return {
                'capacity': self.capacity,
                'available_tokens': self.tokens,
                'refill_rate': self.refill_rate,
                'refill_interval': self.refill_interval,
                'last_refill_time': self.last_refill_time
            }

class RedisTokenBucket:
    """
    Redis-backed Token Bucket for distributed rate limiting

    Uses Redis to store token bucket state for distributed environments
    where multiple WAF instances need to share rate limiting state.
    """

    def __init__(self, redis_client, key: str, capacity: int,
                 refill_rate: float, refill_interval: float = 1.0):
        """
        Initialize Redis-backed token bucket

        Args:
            redis_client: Redis client instance
            key: Unique key for this bucket
            capacity: Maximum number of tokens
            refill_rate: Tokens to add per refill interval
            refill_interval: Time interval in seconds
        """
        self.redis = redis_client
        self.key = f"rate_limit:{key}"
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.refill_interval = refill_interval
        self.lock = threading.Lock()

        # Initialize bucket if it doesn't exist
        if not self.redis.exists(self.key):
            self._initialize_bucket()

    def _initialize_bucket(self):
        """Initialize the bucket in Redis"""
        pipeline = self.redis.pipeline()
        pipeline.hset(self.key, mapping={
            'tokens': str(self.capacity),
            'last_refill': str(time.time())
        })
        pipeline.expire(self.key, int(self.capacity / self.refill_rate) * 2)  # Set reasonable TTL
        pipeline.execute()

    def _refill_tokens(self) -> float:
        """Refill tokens and return current token count"""
        now = time.time()
        bucket_data = self.redis.hgetall(self.key)

        if not bucket_data:
            self._initialize_bucket()
            bucket_data = self.redis.hgetall(self.key)

        last_refill = float(bucket_data.get(b'last_refill', str(now)))
        tokens = float(bucket_data.get(b'tokens', str(self.capacity)))

        elapsed = now - last_refill
        if elapsed > 0:
            tokens_to_add = (elapsed / self.refill_interval) * self.refill_rate
            tokens = min(self.capacity, tokens + tokens_to_add)

        # Update last refill time
        self.redis.hset(self.key, 'last_refill', str(now))
        self.redis.hset(self.key, 'tokens', str(tokens))

        return tokens

    def consume(self, tokens: int = 1) -> bool:
        """
        Consume tokens from the Redis bucket

        Args:
            tokens: Number of tokens to consume

        Returns:
            bool: True if tokens were consumed, False if rate limited
        """
        with self.lock:
            current_tokens = self._refill_tokens()

            if current_tokens >= tokens:
                # Use Redis transaction for atomic operation
                pipeline = self.redis.pipeline()
                pipeline.watch(self.key)

                # Get current tokens again to ensure consistency
                bucket_data = self.redis.hgetall(self.key)
                current_tokens = float(bucket_data.get(b'tokens', '0'))

                if current_tokens >= tokens:
                    pipeline.multi()
                    pipeline.hset(self.key, 'tokens', str(current_tokens - tokens))
                    pipeline.execute()
                    return True
                else:
                    pipeline.unwatch()
                    return False
            return False

    def get_available_tokens(self) -> float:
        """Get current available tokens"""
        with self.lock:
            self._refill_tokens()
            bucket_data = self.redis.hgetall(self.key)
            return float(bucket_data.get(b'tokens', '0'))

    def get_bucket_info(self) -> Dict[str, Union[float, int]]:
        """Get bucket information"""
        with self.lock:
            self._refill_tokens()
            bucket_data = self.redis.hgetall(self.key)
            return {
                'capacity': self.capacity,
                'available_tokens': float(bucket_data.get(b'tokens', '0')),
                'refill_rate': self.refill_rate,
                'refill_interval': self.refill_interval,
                'last_refill_time': float(bucket_data.get(b'last_refill', '0'))
            }

class RateLimiter:
    """
    Comprehensive Rate Limiter for Ariba WAF

    Implements per-IP and per-endpoint rate limiting with token bucket algorithm
    and optional Redis support for distributed environments.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None,
                 security_engine: Optional[SecurityEngine] = None,
                 logger: Optional[LoggingModule] = None):
        """
        Initialize Rate Limiter

        Args:
            config: Configuration dictionary
            security_engine: Security engine instance for integration
            logger: Logging module instance
        """
        # Default configuration
        self.default_config = {
            # Global rate limits
            'global': {
                'enabled': True,
                'capacity': 1000,  # tokens
                'refill_rate': 100,  # tokens per second
                'refill_interval': 1.0  # seconds
            },

            # Per-IP rate limits
            'ip': {
                'enabled': True,
                'capacity': 100,  # tokens
                'refill_rate': 10,  # tokens per second
                'refill_interval': 1.0  # seconds
            },

            # Per-endpoint rate limits
            'endpoint': {
                'enabled': True,
                'capacity': 50,  # tokens
                'refill_rate': 5,  # tokens per second
                'refill_interval': 1.0  # seconds
            },

            # Per-IP+endpoint rate limits
            'ip_endpoint': {
                'enabled': True,
                'capacity': 20,  # tokens
                'refill_rate': 2,  # tokens per second
                'refill_interval': 1.0  # seconds
            },

            # Method-specific rate limits
            'methods': {
                'GET': {
                    'capacity': 60,
                    'refill_rate': 6,
                    'refill_interval': 1.0
                },
                'POST': {
                    'capacity': 30,
                    'refill_rate': 3,
                    'refill_interval': 1.0
                },
                'PUT': {
                    'capacity': 20,
                    'refill_rate': 2,
                    'refill_interval': 1.0
                },
                'DELETE': {
                    'capacity': 10,
                    'refill_rate': 1,
                    'refill_interval': 1.0
                }
            },

            # Redis configuration for distributed rate limiting
            'redis': {
                'enabled': False,
                'host': 'localhost',
                'port': 6379,
                'db': 0,
                'password': None,
                'socket_timeout': 5,
                'connection_pool': None
            },

            # Rate limit response
            'response': {
                'block_status_code': 429,
                'block_message': 'Too Many Requests',
                'retry_after_header': True,
                'retry_after_value': 60  # seconds
            },

            # Advanced settings
            'whitelist': [],  # IPs to whitelist from rate limiting
            'blacklist': [],  # IPs to always rate limit
            'burst_multiplier': 2.0,  # Multiplier for burst capacity
            'logging': {
                'log_rate_limit_events': True,
                'log_level': 'WARNING'
            }
        }

        # Merge configurations with deep merge for nested dictionaries
        self.config = self._deep_merge_configs(self.default_config, config or {})

        # Initialize components
        self.security_engine = security_engine
        self.logger = logger or LoggingModule()

        # Initialize buckets storage
        self.buckets: Dict[str, TokenBucket] = {}
        self.redis_client: Optional[redis.Redis] = None
        self.redis_buckets: Dict[str, RedisTokenBucket] = {}
        self.lock = threading.Lock()

        # Initialize Redis if enabled
        if self.config['redis']['enabled']:
            self._initialize_redis()

        # Log initialization
        self.logger.log_system_event("Rate limiter initialized", LogLevel.INFO)

    def _initialize_redis(self):
        """Initialize Redis connection"""
        if not REDIS_AVAILABLE:
            self.logger.log_system_event(
                "Redis module not available, using in-memory rate limiting only",
                LogLevel.WARNING
            )
            self.redis_client = None
            self.config['redis']['enabled'] = False
            return

        try:
            redis_config = self.config['redis']

            self.redis_client = redis.Redis(
                host=redis_config['host'],
                port=redis_config['port'],
                db=redis_config['db'],
                password=redis_config['password'],
                socket_timeout=redis_config['socket_timeout'],
                connection_pool=redis_config['connection_pool']
            )

            # Test connection
            self.redis_client.ping()

            self.logger.log_system_event(
                f"Redis connection established to {redis_config['host']}:{redis_config['port']}",
                LogLevel.INFO
            )

        except Exception as e:
            self.logger.log_error(
                f"Failed to initialize Redis: {str(e)}",
                exception=e
            )
            self.redis_client = None
            self.config['redis']['enabled'] = False

    def _get_bucket_key(self, scope: RateLimitScope, ip: str, endpoint: str, method: str) -> str:
        """
        Generate a unique key for the bucket based on scope and parameters

        Args:
            scope: Rate limit scope
            ip: Client IP address
            endpoint: Request endpoint
            method: HTTP method

        Returns:
            str: Unique bucket key
        """
        if scope == RateLimitScope.GLOBAL:
            return "global"
        elif scope == RateLimitScope.IP:
            return f"ip:{ip}"
        elif scope == RateLimitScope.ENDPOINT:
            return f"endpoint:{endpoint.lower()}"
        elif scope == RateLimitScope.IP_ENDPOINT:
            return f"ip_endpoint:{ip}:{endpoint.lower()}:{method.upper()}"
        else:
            return f"custom:{scope.value}:{ip}:{endpoint}:{method}"

    def _get_bucket_config(self, scope: RateLimitScope, method: str) -> Dict[str, Any]:
        """
        Get bucket configuration based on scope and method

        Args:
            scope: Rate limit scope
            method: HTTP method

        Returns:
            Dict: Bucket configuration
        """
        config_key = scope.value

        # Check if scope is enabled
        if not self.config[config_key]['enabled']:
            return None

        # Get base configuration
        bucket_config = self.config[config_key].copy()

        # Apply method-specific overrides if available
        if method.upper() in self.config['methods']:
            method_config = self.config['methods'][method.upper()]
            bucket_config.update({
                'capacity': method_config['capacity'],
                'refill_rate': method_config['refill_rate'],
                'refill_interval': method_config['refill_interval']
            })

        return bucket_config

    def _get_or_create_bucket(self, scope: RateLimitScope, ip: str,
                            endpoint: str, method: str) -> Union[TokenBucket, RedisTokenBucket]:
        """
        Get or create a token bucket for the given parameters

        Args:
            scope: Rate limit scope
            ip: Client IP address
            endpoint: Request endpoint
            method: HTTP method

        Returns:
            TokenBucket or RedisTokenBucket instance
        """
        key = self._get_bucket_key(scope, ip, endpoint, method)
        bucket_config = self._get_bucket_config(scope, method)

        if not bucket_config:
            return None

        if self.redis_client and self.config['redis']['enabled']:
            # Use Redis bucket for distributed rate limiting
            if key not in self.redis_buckets:
                with self.lock:
                    if key not in self.redis_buckets:
                        self.redis_buckets[key] = RedisTokenBucket(
                            redis_client=self.redis_client,
                            key=key,
                            capacity=bucket_config['capacity'],
                            refill_rate=bucket_config['refill_rate'],
                            refill_interval=bucket_config['refill_interval']
                        )
            return self.redis_buckets[key]
        else:
            # Use in-memory bucket
            if key not in self.buckets:
                with self.lock:
                    if key not in self.buckets:
                        self.buckets[key] = TokenBucket(
                            capacity=bucket_config['capacity'],
                            refill_rate=bucket_config['refill_rate'],
                            refill_interval=bucket_config['refill_interval']
                        )
            return self.buckets[key]

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted from rate limiting"""
        return ip in self.config['whitelist']

    def _is_blacklisted(self, ip: str) -> bool:
        """Check if IP is blacklisted for rate limiting"""
        return ip in self.config['blacklist']

    def check_rate_limit(self, request_data: Dict[str, Any]) -> Tuple[RateLimitAction, Dict[str, Any]]:
        """
        Check rate limits for a request

        Args:
            request_data: Request data dictionary containing:
                - remote_ip: Client IP address
                - method: HTTP method
                - path: Request path/endpoint
                - headers: Request headers
                - body: Request body

        Returns:
            Tuple of (action, details) where:
            - action: RateLimitAction (ALLOW, BLOCK, CHALLENGE)
            - details: Dictionary with rate limit information
        """
        try:
            # Extract request information
            ip = request_data.get('remote_ip', 'unknown')
            method = request_data.get('method', 'GET').upper()
            endpoint = request_data.get('path', '/').lower()

            # Check whitelist/blacklist
            if self._is_whitelisted(ip):
                return RateLimitAction.ALLOW, {
                    'reason': 'whitelisted',
                    'scope': 'whitelist'
                }

            if self._is_blacklisted(ip):
                return RateLimitAction.BLOCK, {
                    'reason': 'blacklisted',
                    'scope': 'blacklist'
                }

            # Check all enabled rate limit scopes
            rate_limit_results = {}
            overall_action = RateLimitAction.ALLOW

            # Check each scope in order of specificity
            scopes_to_check = [
                RateLimitScope.IP_ENDPOINT,
                RateLimitScope.IP,
                RateLimitScope.ENDPOINT,
                RateLimitScope.GLOBAL
            ]

            for scope in scopes_to_check:
                if not self.config[scope.value]['enabled']:
                    continue

                bucket = self._get_or_create_bucket(scope, ip, endpoint, method)
                if not bucket:
                    continue

                # Try to consume tokens
                tokens_consumed = bucket.consume()

                rate_limit_results[scope.value] = {
                    'scope': scope.value,
                    'tokens_consumed': tokens_consumed,
                    'available_tokens': bucket.get_available_tokens(),
                    'bucket_info': bucket.get_bucket_info(),
                    'rate_limited': not tokens_consumed
                }

                # If any scope is rate limited, take action
                if not tokens_consumed:
                    overall_action = RateLimitAction.BLOCK
                    break  # Stop checking other scopes if rate limited

            # Prepare response
            if overall_action == RateLimitAction.BLOCK:
                response_config = self.config['response']
                details = {
                    'action': 'block',
                    'status_code': response_config['block_status_code'],
                    'message': response_config['block_message'],
                    'retry_after': response_config['retry_after_value'],
                    'rate_limit_results': rate_limit_results,
                    'ip': ip,
                    'endpoint': endpoint,
                    'method': method
                }

                # Log rate limit event
                if self.config['logging']['log_rate_limit_events']:
                    self.logger.log_system_event(
                        f"Rate limit exceeded for {ip} on {method} {endpoint}",
                        getattr(LogLevel, self.config['logging']['log_level'], LogLevel.WARNING)
                    )

                return RateLimitAction.BLOCK, details
            else:
                return RateLimitAction.ALLOW, {
                    'action': 'allow',
                    'rate_limit_results': rate_limit_results,
                    'ip': ip,
                    'endpoint': endpoint,
                    'method': method
                }

        except Exception as e:
            self.logger.log_error(
                f"Error checking rate limit for {request_data.get('remote_ip', 'unknown')}: {str(e)}",
                exception=e
            )
            # Fail open - allow request if rate limiter fails
            return RateLimitAction.ALLOW, {
                'action': 'allow',
                'error': str(e),
                'reason': 'rate_limiter_error'
            }

    def get_rate_limit_status(self, ip: str, endpoint: str, method: str = 'GET') -> Dict[str, Any]:
        """
        Get current rate limit status for a specific IP/endpoint

        Args:
            ip: Client IP address
            endpoint: Request endpoint
            method: HTTP method

        Returns:
            Dictionary with rate limit status information
        """
        try:
            status = {
                'ip': ip,
                'endpoint': endpoint,
                'method': method.upper(),
                'timestamp': datetime.now().isoformat(),
                'scopes': {}
            }

            # Check each scope
            for scope in [RateLimitScope.GLOBAL, RateLimitScope.IP,
                         RateLimitScope.ENDPOINT, RateLimitScope.IP_ENDPOINT]:

                if not self.config[scope.value]['enabled']:
                    continue

                bucket = self._get_or_create_bucket(scope, ip, endpoint, method)
                if bucket:
                    status['scopes'][scope.value] = {
                        'available_tokens': bucket.get_available_tokens(),
                        'bucket_info': bucket.get_bucket_info()
                    }

            return status

        except Exception as e:
            self.logger.log_error(f"Error getting rate limit status: {str(e)}", exception=e)
            return {
                'error': str(e),
                'ip': ip,
                'endpoint': endpoint,
                'method': method
            }

    def update_config(self, new_config: Dict[str, Any]):
        """
        Update rate limiter configuration

        Args:
            new_config: Dictionary with new configuration values
        """
        with self.lock:
            # Deep merge configuration
            self._deep_update_config(self.config, new_config)

            # Reinitialize Redis if configuration changed
            if 'redis' in new_config and self.config['redis']['enabled']:
                self._initialize_redis()

            self.logger.log_system_event("Rate limiter configuration updated", LogLevel.INFO)

    def _deep_merge_configs(self, target: Dict, source: Dict) -> Dict:
        """Deep merge configuration dictionaries"""
        result = target.copy()
        for key, value in source.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge_configs(result[key], value)
            else:
                result[key] = value
        return result

    def _deep_update_config(self, target: Dict, source: Dict):
        """Deep update configuration dictionary"""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_update_config(target[key], value)
            else:
                target[key] = value

    def reset_buckets(self):
        """Reset all in-memory buckets (useful for testing)"""
        with self.lock:
            self.buckets.clear()
            self.logger.log_system_event("Rate limiter buckets reset", LogLevel.INFO)

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        return {
            'buckets_count': len(self.buckets),
            'redis_buckets_count': len(self.redis_buckets),
            'redis_enabled': self.config['redis']['enabled'],
            'redis_connected': self.redis_client is not None,
            'config': {
                'global_enabled': self.config['global']['enabled'],
                'ip_enabled': self.config['ip']['enabled'],
                'endpoint_enabled': self.config['endpoint']['enabled'],
                'ip_endpoint_enabled': self.config['ip_endpoint']['enabled']
            }
        }

    def integrate_with_security_engine(self, security_engine: SecurityEngine):
        """Integrate with security engine"""
        self.security_engine = security_engine
        self.logger.log_system_event("Rate limiter integrated with security engine", LogLevel.INFO)

# Example usage and testing
if __name__ == "__main__":
    # Example configuration
    config = {
        'ip': {
            'capacity': 10,
            'refill_rate': 1,
            'refill_interval': 1.0
        },
        'redis': {
            'enabled': False  # Set to True if Redis is available
        },
        'logging': {
            'log_rate_limit_events': True
        }
    }

    # Create rate limiter
    rate_limiter = RateLimiter(config=config)

    # Example request data
    request_data = {
        'remote_ip': '192.168.1.100',
        'method': 'GET',
        'path': '/api/test',
        'headers': {
            'User-Agent': 'Test Client'
        }
    }

    # Test rate limiting
    print("Testing rate limiter...")
    for i in range(15):
        action, details = rate_limiter.check_rate_limit(request_data)
        print(f"Request {i+1}: {action.value} - {details.get('reason', 'allowed')}")
        if action == RateLimitAction.BLOCK:
            print(f"  Rate limited! Retry after: {details.get('retry_after', 'N/A')} seconds")
            break
        time.sleep(0.1)  # Small delay between requests

    # Get rate limit status
    status = rate_limiter.get_rate_limit_status('192.168.1.100', '/api/test', 'GET')
    print(f"\nRate limit status: {json.dumps(status, indent=2)}")

    # Get stats
    stats = rate_limiter.get_stats()
    print(f"\nRate limiter stats: {json.dumps(stats, indent=2)}")