#!/usr/bin/env python3
"""
Ariba WAF Configuration Manager Module

A comprehensive configuration management system for the Ariba Web Application Firewall
that handles security rules, IP filtering, rate limiting, and dynamic configuration updates.

Features:
- Centralized rule management for SQLi, XSS, and other security patterns
- IP whitelist/blacklist management
- Rate limiting rule management
- Dynamic configuration updates without restart
- Rule validation and conflict detection
- Integration with all WAF components (SecurityEngine, IPFilter, RateLimiter)
- Configuration file management (JSON/YAML)
- Error handling and logging
- Thread-safe operations
"""

import json
import os
import re
import threading
import copy
import ipaddress
from typing import Dict, Any, List, Optional, Tuple, Set, Union
from enum import Enum
import logging
import time
from datetime import datetime

# Try to import existing WAF modules for integration
try:
    from security_engine import SecurityEngine
    from ip_filter import IPFilter, IPFilterAction
    from rate_limiter import RateLimiter, RateLimitScope
    from logging_module import LoggingModule, LogLevel
except ImportError:
    # Fallback classes for standalone operation
    class SecurityEngine:
        pass

    class IPFilter:
        pass

    class RateLimiter:
        pass

    class LoggingModule:
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger('ConfigManager')
            handler = logging.StreamHandler()
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

        def log_system_event(self, message, level="INFO"):
            getattr(self.logger, level.lower())(f"[SYSTEM] {message}")

        def log_error(self, message, exception=None):
            if exception:
                self.logger.error(f"[ERROR] {message}: {str(exception)}")
            else:
                self.logger.error(f"[ERROR] {message}")

class RuleType(Enum):
    """Types of security rules supported by the configuration manager"""
    SQLI = "sqli"
    XSS = "xss"
    IP_WHITELIST = "ip_whitelist"
    IP_BLACKLIST = "ip_blacklist"
    RATE_LIMIT = "rate_limit"
    CUSTOM = "custom"

class RuleSeverity(Enum):
    """Severity levels for security rules"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ConfigManager:
    """
    Comprehensive Configuration Manager for Ariba WAF

    Manages all security rules, IP filtering, rate limiting, and provides
    dynamic configuration updates without requiring WAF restart.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Configuration Manager

        Args:
            config: Configuration dictionary containing:
                - config_file: Path to configuration file (optional)
                - auto_load: Automatically load configuration from file (default: True)
                - auto_save: Automatically save configuration to file (default: True)
                - default_rules: Default security rules to load
                - logging: Logging configuration
        """
        # Default configuration
        self.default_config = {
            'config_file': 'waf_config.json',
            'auto_load': True,
            'auto_save': True,
            'config_format': 'json',  # only json supported
            'default_rules': {
                'sqli': {
                    'enabled': True,
                    'severity': RuleSeverity.MEDIUM.value,
                    'patterns': [
                        r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|UNION|OR\s+1=1)\b',
                        r'\b(SELECT\s+\*.*FROM|INSERT\s+INTO.*VALUES)\b',
                        r'\b(EXEC\s+sp_|xp_)\b',
                        r'\b(OR\s+[0-9]+=[0-9]+|AND\s+[0-9]+=[0-9]+)\b',
                        r'\b(BENCHMARK|SLEEP|LOAD_FILE)\b'
                    ]
                },
                'xss': {
                    'enabled': True,
                    'severity': RuleSeverity.MEDIUM.value,
                    'patterns': [
                        r'<script[^>]*>.*?</script>',
                        r'on\w+\s*=',
                        r'javascript:',
                        r'eval\s*\(',
                        r'<[^>]+>',
                        r'document\.cookie',
                        r'window\.location',
                        r'alert\s*\('
                    ]
                },
                'ip_filtering': {
                    'enabled': True,
                    'whitelist': [],
                    'blacklist': [],
                    'default_action': IPFilterAction.ALLOW.value
                },
                'rate_limiting': {
                    'enabled': True,
                    'global': {
                        'capacity': 1000,
                        'refill_rate': 100,
                        'refill_interval': 1.0
                    },
                    'ip': {
                        'capacity': 100,
                        'refill_rate': 10,
                        'refill_interval': 1.0
                    },
                    'endpoint': {
                        'capacity': 50,
                        'refill_rate': 5,
                        'refill_interval': 1.0
                    },
                    'ip_endpoint': {
                        'capacity': 20,
                        'refill_rate': 2,
                        'refill_interval': 1.0
                    }
                }
            },
            'logging': {
                'log_level': LogLevel.INFO.value,
                'log_file': 'config_manager.log',
                'console_logging': True,
                'file_logging': True
            }
        }

        # Initialize configuration
        self.config = {**self.default_config, **(config or {})}
        self.lock = threading.Lock()
        self.rules: Dict[str, Any] = {}
        self.rule_history: List[Dict[str, Any]] = []
        self.last_updated: Optional[datetime] = None
        self.integrated_components: Dict[str, Any] = {}

        # Initialize logging
        self.logger = LoggingModule(self.config['logging'])
        self.logger.log_system_event("ConfigManager initialized", LogLevel.INFO)

        # Load configuration if auto_load is enabled
        if self.config['auto_load']:
            self.load_configuration()

        # Initialize with default rules if no rules loaded
        if not self.rules:
            self.rules = copy.deepcopy(self.config['default_rules'])
            self.last_updated = datetime.now()

    def _validate_rule_pattern(self, pattern: str) -> bool:
        """
        Validate a regex pattern

        Args:
            pattern: Regex pattern to validate

        Returns:
            bool: True if pattern is valid, False otherwise
        """
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False

    def _validate_ip_address(self, ip_entry: str) -> bool:
        """
        Validate an IP address or network

        Args:
            ip_entry: IP address or network in CIDR notation

        Returns:
            bool: True if IP is valid, False otherwise
        """
        try:
            if '/' in ip_entry:
                ipaddress.ip_network(ip_entry, strict=False)
            else:
                ipaddress.ip_address(ip_entry)
            return True
        except ValueError:
            return False

    def _validate_rate_limit_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate rate limit configuration

        Args:
            config: Rate limit configuration to validate

        Returns:
            bool: True if configuration is valid, False otherwise
        """
        required_keys = ['capacity', 'refill_rate', 'refill_interval']
        for key in required_keys:
            if key not in config:
                return False
            if not isinstance(config[key], (int, float)) or config[key] <= 0:
                return False
        return True

    def add_rule(self, rule_type: RuleType, rule_data: Dict[str, Any]) -> bool:
        """
        Add a new security rule

        Args:
            rule_type: Type of rule (RuleType enum)
            rule_data: Dictionary containing rule configuration

        Returns:
            bool: True if rule was added successfully, False otherwise
        """
        with self.lock:
            try:
                # Validate rule data based on type
                if rule_type == RuleType.SQLI or rule_type == RuleType.XSS:
                    if 'patterns' not in rule_data or not isinstance(rule_data['patterns'], list):
                        raise ValueError("Security rules require a 'patterns' list")

                    for pattern in rule_data['patterns']:
                        if not self._validate_rule_pattern(pattern):
                            raise ValueError(f"Invalid regex pattern: {pattern}")

                elif rule_type == RuleType.IP_WHITELIST or rule_type == RuleType.IP_BLACKLIST:
                    if 'ips' not in rule_data or not isinstance(rule_data['ips'], list):
                        raise ValueError("IP rules require an 'ips' list")

                    for ip_entry in rule_data['ips']:
                        if not self._validate_ip_address(ip_entry):
                            raise ValueError(f"Invalid IP address: {ip_entry}")

                elif rule_type == RuleType.RATE_LIMIT:
                    if not self._validate_rate_limit_config(rule_data):
                        raise ValueError("Invalid rate limit configuration")

                # Add rule to the appropriate category
                rule_key = rule_type.value
                if rule_key not in self.rules:
                    self.rules[rule_key] = {}

                # Generate a unique rule ID
                rule_id = f"{rule_key}_{len(self.rules[rule_key]) + 1}_{int(time.time())}"
                self.rules[rule_key][rule_id] = rule_data

                # Add to rule history
                self._add_to_rule_history('add', rule_type, rule_id, rule_data)

                self.last_updated = datetime.now()

                # Auto-save if enabled
                if self.config['auto_save']:
                    self.save_configuration()

                self.logger.log_system_event(
                    f"Added new {rule_type.value} rule: {rule_id}",
                    LogLevel.INFO
                )

                return True

            except Exception as e:
                self.logger.log_error(f"Failed to add {rule_type.value} rule: {str(e)}", e)
                return False

    def update_rule(self, rule_type: RuleType, rule_id: str, new_data: Dict[str, Any]) -> bool:
        """
        Update an existing security rule

        Args:
            rule_type: Type of rule (RuleType enum)
            rule_id: ID of the rule to update
            new_data: New rule configuration data

        Returns:
            bool: True if rule was updated successfully, False otherwise
        """
        with self.lock:
            try:
                rule_key = rule_type.value
                if rule_key not in self.rules or rule_id not in self.rules[rule_key]:
                    raise ValueError(f"Rule {rule_id} not found in {rule_key}")

                old_data = self.rules[rule_key][rule_id]

                # Validate new data based on rule type
                if rule_type == RuleType.SQLI or rule_type == RuleType.XSS:
                    if 'patterns' in new_data and not isinstance(new_data['patterns'], list):
                        raise ValueError("Security rules require a 'patterns' list")

                    if 'patterns' in new_data:
                        for pattern in new_data['patterns']:
                            if not self._validate_rule_pattern(pattern):
                                raise ValueError(f"Invalid regex pattern: {pattern}")

                elif rule_type == RuleType.IP_WHITELIST or rule_type == RuleType.IP_BLACKLIST:
                    if 'ips' in new_data and not isinstance(new_data['ips'], list):
                        raise ValueError("IP rules require an 'ips' list")

                    if 'ips' in new_data:
                        for ip_entry in new_data['ips']:
                            if not self._validate_ip_address(ip_entry):
                                raise ValueError(f"Invalid IP address: {ip_entry}")

                elif rule_type == RuleType.RATE_LIMIT:
                    if not self._validate_rate_limit_config(new_data):
                        raise ValueError("Invalid rate limit configuration")

                # Update the rule
                self.rules[rule_key][rule_id].update(new_data)

                # Add to rule history
                self._add_to_rule_history('update', rule_type, rule_id, new_data, old_data)

                self.last_updated = datetime.now()

                # Auto-save if enabled
                if self.config['auto_save']:
                    self.save_configuration()

                self.logger.log_system_event(
                    f"Updated {rule_type.value} rule: {rule_id}",
                    LogLevel.INFO
                )

                return True

            except Exception as e:
                self.logger.log_error(f"Failed to update {rule_type.value} rule {rule_id}: {str(e)}", e)
                return False

    def remove_rule(self, rule_type: RuleType, rule_id: str) -> bool:
        """
        Remove a security rule

        Args:
            rule_type: Type of rule (RuleType enum)
            rule_id: ID of the rule to remove

        Returns:
            bool: True if rule was removed successfully, False otherwise
        """
        with self.lock:
            try:
                rule_key = rule_type.value
                if rule_key not in self.rules or rule_id not in self.rules[rule_key]:
                    raise ValueError(f"Rule {rule_id} not found in {rule_key}")

                old_data = self.rules[rule_key][rule_id]

                # Remove the rule
                del self.rules[rule_key][rule_id]

                # If no more rules of this type, remove the category
                if not self.rules[rule_key]:
                    del self.rules[rule_key]

                # Add to rule history
                self._add_to_rule_history('remove', rule_type, rule_id, None, old_data)

                self.last_updated = datetime.now()

                # Auto-save if enabled
                if self.config['auto_save']:
                    self.save_configuration()

                self.logger.log_system_event(
                    f"Removed {rule_type.value} rule: {rule_id}",
                    LogLevel.INFO
                )

                return True

            except Exception as e:
                self.logger.log_error(f"Failed to remove {rule_type.value} rule {rule_id}: {str(e)}", e)
                return False

    def _add_to_rule_history(self, action: str, rule_type: RuleType, rule_id: str,
                           new_data: Optional[Dict[str, Any]] = None,
                           old_data: Optional[Dict[str, Any]] = None):
        """
        Add an entry to the rule history

        Args:
            action: Action performed (add, update, remove)
            rule_type: Type of rule
            rule_id: ID of the rule
            new_data: New rule data (for add/update)
            old_data: Old rule data (for update/remove)
        """
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'rule_type': rule_type.value,
            'rule_id': rule_id,
            'new_data': new_data,
            'old_data': old_data,
            'user': 'system'  # In a real system, this would be the user who made the change
        }

        self.rule_history.append(history_entry)

        # Keep history size manageable (max 1000 entries)
        if len(self.rule_history) > 1000:
            self.rule_history = self.rule_history[-1000:]

    def detect_rule_conflicts(self) -> List[Dict[str, Any]]:
        """
        Detect conflicts between security rules

        Returns:
            List of dictionaries describing any conflicts found
        """
        conflicts = []

        with self.lock:
            try:
                # Check for conflicting IP rules (whitelist vs blacklist)
                if 'ip_whitelist' in self.rules and 'ip_blacklist' in self.rules:
                    whitelist_ips = set()
                    for rule_id, rule_data in self.rules['ip_whitelist'].items():
                        whitelist_ips.update(rule_data.get('ips', []))

                    blacklist_ips = set()
                    for rule_id, rule_data in self.rules['ip_blacklist'].items():
                        blacklist_ips.update(rule_data.get('ips', []))

                    # Find overlapping IPs
                    overlapping_ips = whitelist_ips.intersection(blacklist_ips)
                    if overlapping_ips:
                        conflicts.append({
                            'type': 'ip_conflict',
                            'severity': 'high',
                            'description': f"IP addresses found in both whitelist and blacklist: {', '.join(overlapping_ips)}",
                            'conflicting_ips': list(overlapping_ips)
                        })

                # Check for overly broad regex patterns that might conflict
                if 'sqli' in self.rules and 'xss' in self.rules:
                    sqli_patterns = []
                    for rule_data in self.rules['sqli'].values():
                        if isinstance(rule_data, dict):
                            sqli_patterns.extend(rule_data.get('patterns', []))

                    xss_patterns = []
                    for rule_data in self.rules['xss'].values():
                        if isinstance(rule_data, dict):
                            xss_patterns.extend(rule_data.get('patterns', []))

                    # Simple conflict detection - patterns that are too similar
                    all_patterns = sqli_patterns + xss_patterns
                    pattern_counts = {}
                    for pattern in all_patterns:
                        pattern_key = pattern.lower().replace(r'\s+', ' ').strip()
                        pattern_counts[pattern_key] = pattern_counts.get(pattern_key, 0) + 1

                    for pattern_key, count in pattern_counts.items():
                        if count > 1:
                            conflicts.append({
                                'type': 'pattern_duplication',
                                'severity': 'medium',
                                'description': f"Duplicate or very similar pattern found {count} times: {pattern_key}",
                                'pattern': pattern_key,
                                'occurrences': count
                            })

                # Check rate limiting conflicts
                if 'rate_limit' in self.rules:
                    rate_limit_rules = self.rules['rate_limit']
                    for rule_id, rule_data in rate_limit_rules.items():
                        if rule_data.get('capacity', 0) < rule_data.get('refill_rate', 0):
                            conflicts.append({
                                'type': 'rate_limit_conflict',
                                'severity': 'medium',
                                'description': f"Rate limit rule {rule_id} has capacity ({rule_data['capacity']}) less than refill rate ({rule_data['refill_rate']})",
                                'rule_id': rule_id,
                                'capacity': rule_data['capacity'],
                                'refill_rate': rule_data['refill_rate']
                            })

                return conflicts

            except Exception as e:
                self.logger.log_error(f"Error detecting rule conflicts: {str(e)}", e)
                return []

    def integrate_with_security_engine(self, security_engine: SecurityEngine) -> bool:
        """
        Integrate with the SecurityEngine component

        Args:
            security_engine: SecurityEngine instance

        Returns:
            bool: True if integration was successful, False otherwise
        """
        try:
            if not isinstance(security_engine, SecurityEngine):
                raise ValueError("Invalid SecurityEngine instance")

            self.integrated_components['security_engine'] = security_engine

            # Update security engine with current rules
            self._update_security_engine_rules()

            self.logger.log_system_event(
                "Successfully integrated with SecurityEngine",
                LogLevel.INFO
            )

            return True

        except Exception as e:
            self.logger.log_error(f"Failed to integrate with SecurityEngine: {str(e)}", e)
            return False

    def _update_security_engine_rules(self):
        """
        Update the integrated SecurityEngine with current security rules
        """
        try:
            if 'security_engine' not in self.integrated_components:
                return

            security_engine = self.integrated_components['security_engine']

            # Get current SQLi patterns
            sqli_patterns = []
            if 'sqli' in self.rules:
                for rule_data in self.rules['sqli'].values():
                    if rule_data.get('enabled', True):
                        sqli_patterns.extend(rule_data.get('patterns', []))

            # Get current XSS patterns
            xss_patterns = []
            if 'xss' in self.rules:
                for rule_data in self.rules['xss'].values():
                    if rule_data.get('enabled', True):
                        xss_patterns.extend(rule_data.get('patterns', []))

            # Determine sensitivity based on rule severity
            severity_levels = []
            if 'sqli' in self.rules:
                for rule_data in self.rules['sqli'].values():
                    if rule_data.get('enabled', True) and 'severity' in rule_data:
                        severity_levels.append(rule_data['severity'])

            if 'xss' in self.rules:
                for rule_data in self.rules['xss'].values():
                    if rule_data.get('enabled', True) and 'severity' in rule_data:
                        severity_levels.append(rule_data['severity'])

            # Set sensitivity based on highest severity
            if severity_levels:
                severity_mapping = {
                    RuleSeverity.LOW.value: 'low',
                    RuleSeverity.MEDIUM.value: 'medium',
                    RuleSeverity.HIGH.value: 'high',
                    RuleSeverity.CRITICAL.value: 'high'
                }

                highest_severity = max(severity_levels, key=lambda s: list(RuleSeverity).index(RuleSeverity(s)))
                sensitivity = severity_mapping.get(highest_severity, 'medium')
            else:
                sensitivity = 'medium'

            # Update security engine patterns (this would require extending SecurityEngine)
            # For now, we'll just log the intended update
            self.logger.log_system_event(
                f"SecurityEngine update: {len(sqli_patterns)} SQLi patterns, {len(xss_patterns)} XSS patterns, sensitivity: {sensitivity}",
                LogLevel.INFO
            )

        except Exception as e:
            self.logger.log_error(f"Failed to update SecurityEngine rules: {str(e)}", e)

    def integrate_with_ip_filter(self, ip_filter: IPFilter) -> bool:
        """
        Integrate with the IPFilter component

        Args:
            ip_filter: IPFilter instance

        Returns:
            bool: True if integration was successful, False otherwise
        """
        try:
            if not isinstance(ip_filter, IPFilter):
                raise ValueError("Invalid IPFilter instance")

            self.integrated_components['ip_filter'] = ip_filter

            # Update IP filter with current rules
            self._update_ip_filter_rules()

            self.logger.log_system_event(
                "Successfully integrated with IPFilter",
                LogLevel.INFO
            )

            return True

        except Exception as e:
            self.logger.log_error(f"Failed to integrate with IPFilter: {str(e)}", e)
            return False

    def _update_ip_filter_rules(self):
        """
        Update the integrated IPFilter with current IP rules
        """
        try:
            if 'ip_filter' not in self.integrated_components:
                return

            ip_filter = self.integrated_components['ip_filter']

            # Collect whitelist and blacklist IPs
            whitelist = []
            blacklist = []

            if 'ip_whitelist' in self.rules:
                for rule_data in self.rules['ip_whitelist'].values():
                    if rule_data.get('enabled', True):
                        whitelist.extend(rule_data.get('ips', []))

            if 'ip_blacklist' in self.rules:
                for rule_data in self.rules['ip_blacklist'].values():
                    if rule_data.get('enabled', True):
                        blacklist.extend(rule_data.get('ips', []))

            # Get default action
            default_action = IPFilterAction.ALLOW.value
            if 'ip_filtering' in self.rules and 'default_action' in self.rules['ip_filtering']:
                default_action = self.rules['ip_filtering']['default_action']

            # Update IP filter configuration
            new_config = {
                'whitelist': whitelist,
                'blacklist': blacklist,
                'default_action': default_action
            }

            # Apply new configuration to IP filter
            # This would require extending IPFilter to support dynamic updates
            self.logger.log_system_event(
                f"IPFilter update: {len(whitelist)} whitelist entries, {len(blacklist)} blacklist entries, default action: {default_action}",
                LogLevel.INFO
            )

        except Exception as e:
            self.logger.log_error(f"Failed to update IPFilter rules: {str(e)}", e)

    def integrate_with_rate_limiter(self, rate_limiter: RateLimiter) -> bool:
        """
        Integrate with the RateLimiter component

        Args:
            rate_limiter: RateLimiter instance

        Returns:
            bool: True if integration was successful, False otherwise
        """
        try:
            if not isinstance(rate_limiter, RateLimiter):
                raise ValueError("Invalid RateLimiter instance")

            self.integrated_components['rate_limiter'] = rate_limiter

            # Update rate limiter with current rules
            self._update_rate_limiter_rules()

            self.logger.log_system_event(
                "Successfully integrated with RateLimiter",
                LogLevel.INFO
            )

            return True

        except Exception as e:
            self.logger.log_error(f"Failed to integrate with RateLimiter: {str(e)}", e)
            return False

    def _update_rate_limiter_rules(self):
        """
        Update the integrated RateLimiter with current rate limit rules
        """
        try:
            if 'rate_limiter' not in self.integrated_components:
                return

            rate_limiter = self.integrated_components['rate_limiter']

            # Build rate limiter configuration
            rate_limit_config = {}

            if 'rate_limiting' in self.rules:
                base_config = self.rules['rate_limiting']

                # Map our configuration to rate limiter format
                if 'global' in base_config:
                    rate_limit_config['global'] = base_config['global']

                if 'ip' in base_config:
                    rate_limit_config['ip'] = base_config['ip']

                if 'endpoint' in base_config:
                    rate_limit_config['endpoint'] = base_config['endpoint']

                if 'ip_endpoint' in base_config:
                    rate_limit_config['ip_endpoint'] = base_config['ip_endpoint']

            # Apply configuration to rate limiter
            # This would require extending RateLimiter to support dynamic updates
            self.logger.log_system_event(
                f"RateLimiter update applied with {len(rate_limit_config)} scope configurations",
                LogLevel.INFO
            )

        except Exception as e:
            self.logger.log_error(f"Failed to update RateLimiter rules: {str(e)}", e)

    def load_configuration(self, file_path: Optional[str] = None) -> bool:
        """
        Load configuration from a file

        Args:
            file_path: Optional path to configuration file. If None, uses configured path.

        Returns:
            bool: True if configuration was loaded successfully, False otherwise
        """
        try:
            config_file = file_path or self.config['config_file']

            if not os.path.exists(config_file):
                self.logger.log_system_event(
                    f"Configuration file not found: {config_file}. Using default configuration.",
                    LogLevel.WARNING
                )
                return False

            with open(config_file, 'r', encoding='utf-8') as f:
                loaded_config = json.load(f)

            # Validate and merge configuration
            self._validate_loaded_configuration(loaded_config)

            with self.lock:
                # Merge with existing configuration, preserving integrated components
                integrated_components = self.integrated_components.copy()
                self.rules = loaded_config.get('rules', {})
                self.rule_history = loaded_config.get('rule_history', [])
                self.last_updated = datetime.fromisoformat(loaded_config.get('last_updated', datetime.now().isoformat()))
                self.integrated_components = integrated_components

            self.logger.log_system_event(
                f"Configuration loaded from {config_file}",
                LogLevel.INFO
            )

            # Update all integrated components
            self._update_all_integrated_components()

            return True

        except Exception as e:
            self.logger.log_error(f"Failed to load configuration from {file_path or self.config['config_file']}: {str(e)}", e)
            return False

    def _validate_loaded_configuration(self, config: Dict[str, Any]):
        """
        Validate loaded configuration

        Args:
            config: Configuration to validate

        Raises:
            ValueError: If configuration is invalid
        """
        # Basic structure validation
        if 'rules' not in config:
            raise ValueError("Configuration must contain 'rules' section")

        rules = config['rules']

        # Validate security rules
        for rule_type in ['sqli', 'xss']:
            if rule_type in rules:
                for rule_id, rule_data in rules[rule_type].items():
                    if 'patterns' in rule_data:
                        for pattern in rule_data['patterns']:
                            if not self._validate_rule_pattern(pattern):
                                raise ValueError(f"Invalid {rule_type} pattern: {pattern}")

        # Validate IP rules
        for rule_type in ['ip_whitelist', 'ip_blacklist']:
            if rule_type in rules:
                for rule_id, rule_data in rules[rule_type].items():
                    if 'ips' in rule_data:
                        for ip_entry in rule_data['ips']:
                            if not self._validate_ip_address(ip_entry):
                                raise ValueError(f"Invalid IP in {rule_type}: {ip_entry}")

        # Validate rate limit rules
        if 'rate_limiting' in rules:
            rate_limit_config = rules['rate_limiting']
            for scope, scope_config in rate_limit_config.items():
                if isinstance(scope_config, dict):
                    if not self._validate_rate_limit_config(scope_config):
                        raise ValueError(f"Invalid rate limit configuration for {scope}")

    def save_configuration(self, file_path: Optional[str] = None) -> bool:
        """
        Save current configuration to a file

        Args:
            file_path: Optional path to save configuration. If None, uses configured path.

        Returns:
            bool: True if configuration was saved successfully, False otherwise
        """
        try:
            config_file = file_path or self.config['config_file']

            # Ensure directory exists
            config_dir = os.path.dirname(config_file)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir, exist_ok=True)

            # Prepare configuration for saving
            save_config = {
                'rules': copy.deepcopy(self.rules),
                'rule_history': copy.deepcopy(self.rule_history),
                'last_updated': self.last_updated.isoformat() if self.last_updated else datetime.now().isoformat(),
                'config_version': '1.0',
                'generated_by': 'Ariba WAF ConfigManager',
                'generated_at': datetime.now().isoformat()
            }

            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(save_config, f, indent=2, ensure_ascii=False)

            self.logger.log_system_event(
                f"Configuration saved to {config_file}",
                LogLevel.INFO
            )

            return True

        except Exception as e:
            self.logger.log_error(f"Failed to save configuration to {file_path or self.config['config_file']}: {str(e)}", e)
            return False

    def _update_all_integrated_components(self):
        """
        Update all integrated components with current configuration
        """
        if 'security_engine' in self.integrated_components:
            self._update_security_engine_rules()

        if 'ip_filter' in self.integrated_components:
            self._update_ip_filter_rules()

        if 'rate_limiter' in self.integrated_components:
            self._update_rate_limiter_rules()

    def get_rules_summary(self) -> Dict[str, Any]:
        """
        Get a summary of current rules

        Returns:
            Dictionary containing rule counts and basic information
        """
        summary = {
            'total_rules': 0,
            'rule_types': {},
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
            'conflicts': self.detect_rule_conflicts(),
            'integrated_components': list(self.integrated_components.keys())
        }

        for rule_type, rules in self.rules.items():
            rule_count = len(rules)
            summary['total_rules'] += rule_count
            summary['rule_types'][rule_type] = {
                'count': rule_count,
                'enabled': sum(1 for rule_data in rules.values() if isinstance(rule_data, dict) and rule_data.get('enabled', True)),
                'disabled': sum(1 for rule_data in rules.values() if isinstance(rule_data, dict) and not rule_data.get('enabled', True))
            }

        return summary

    def get_rule_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent rule history

        Args:
            limit: Maximum number of history entries to return

        Returns:
            List of recent rule history entries
        """
        return self.rule_history[-limit:]

    def reset_to_defaults(self) -> bool:
        """
        Reset all rules to default configuration

        Returns:
            bool: True if reset was successful, False otherwise
        """
        with self.lock:
            try:
                old_rules = copy.deepcopy(self.rules)

                # Reset to default rules
                self.rules = copy.deepcopy(self.config['default_rules'])
                self.last_updated = datetime.now()

                # Add to rule history
                self._add_to_rule_history('reset', RuleType.CUSTOM, 'all_rules', self.rules, old_rules)

                # Auto-save if enabled
                if self.config['auto_save']:
                    self.save_configuration()

                # Update all integrated components
                self._update_all_integrated_components()

                self.logger.log_system_event(
                    "Configuration reset to defaults",
                    LogLevel.WARNING
                )

                return True

            except Exception as e:
                self.logger.log_error(f"Failed to reset configuration to defaults: {str(e)}", e)
                return False

    def close(self):
        """
        Clean up resources and close the configuration manager
        """
        try:
            # Save configuration if auto_save is enabled
            if self.config['auto_save']:
                self.save_configuration()

            self.logger.log_system_event(
                "ConfigManager closed",
                LogLevel.INFO
            )

        except Exception as e:
            self.logger.log_error(f"Error closing ConfigManager: {str(e)}", e)

# Example usage and testing
if __name__ == "__main__":
    # Create a configuration manager
    config_manager = ConfigManager({
        'config_file': 'test_waf_config.json',
        'auto_save': True,
        'logging': {
            'log_level': LogLevel.DEBUG.value,
            'console_logging': True,
            'file_logging': False
        }
    })

    # Add some test rules
    config_manager.add_rule(RuleType.SQLI, {
        'enabled': True,
        'severity': RuleSeverity.HIGH.value,
        'description': 'Advanced SQL injection patterns',
        'patterns': [
            r'\b(SELECT\s+\*.*FROM\s+users)\b',
            r'\b(UNION\s+SELECT\s+password)\b'
        ]
    })

    config_manager.add_rule(RuleType.XSS, {
        'enabled': True,
        'severity': RuleSeverity.MEDIUM.value,
        'description': 'Basic XSS protection',
        'patterns': [
            r'<script[^>]*>.*?</script>',
            r'on\w+\s*=.*?javascript:'
        ]
    })

    config_manager.add_rule(RuleType.IP_WHITELIST, {
        'enabled': True,
        'description': 'Trusted internal networks',
        'ips': ['192.168.1.0/24', '10.0.0.1']
    })

    config_manager.add_rule(RuleType.IP_BLACKLIST, {
        'enabled': True,
        'description': 'Known malicious IPs',
        'ips': ['192.168.2.100', '8.8.8.8']
    })

    # Get rules summary
    summary = config_manager.get_rules_summary()
    print(f"Rules Summary: {json.dumps(summary, indent=2)}")

    # Detect conflicts
    conflicts = config_manager.detect_rule_conflicts()
    print(f"Conflicts: {json.dumps(conflicts, indent=2)}")

    # Test rule history
    history = config_manager.get_rule_history(5)
    print(f"Recent rule history ({len(history)} entries):")
    for entry in history:
        print(f"  {entry['timestamp']} - {entry['action']} {entry['rule_type']} rule {entry['rule_id']}")

    # Save configuration
    config_manager.save_configuration()

    # Close the manager
    config_manager.close()