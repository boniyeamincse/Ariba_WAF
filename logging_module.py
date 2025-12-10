#!/usr/bin/env python3
"""
Ariba WAF Logging Module

A comprehensive logging system for the Ariba Web Application Firewall that supports:
- Multiple logging formats (JSON, plain text)
- Different log levels (INFO, WARNING, ERROR)
- Log rotation and file management
- Detailed request logging with timestamps, IP, payload, headers
- Both file-based and console logging
- Integration with other WAF modules
"""

import json
import logging
import logging.handlers
import os
import time
import threading
from datetime import datetime
from typing import Dict, Any, Optional, Union, List
from enum import Enum
import hashlib
import socket
import platform
import traceback

class LogLevel(Enum):
    """Log levels for the logging module"""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    DEBUG = "DEBUG"
    CRITICAL = "CRITICAL"

class LogFormat(Enum):
    """Supported log formats"""
    JSON = "json"
    TEXT = "text"
    CSV = "csv"

class LoggingModule:
    """
    Comprehensive Logging Module for Ariba WAF

    Features:
    - Configurable logging system with multiple formats
    - Log rotation and retention policies
    - Detailed request logging with timestamps, IP, payload, headers
    - Support for both file-based and console logging
    - Error handling and validation
    - Integration with other WAF modules
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the LoggingModule

        Args:
            config: Configuration dictionary containing:
                - log_dir: Directory for log files (default: 'logs')
                - log_file: Base log file name (default: 'ariba_waf')
                - max_bytes: Maximum log file size before rotation (default: 10MB)
                - backup_count: Number of backup log files to keep (default: 5)
                - log_level: Minimum log level (default: INFO)
                - log_format: Log format (json, text, csv) (default: json)
                - console_logging: Enable console logging (default: True)
                - file_logging: Enable file logging (default: True)
                - include_system_info: Include system information in logs (default: True)
        """
        # Default configuration
        self.default_config = {
            'log_dir': 'logs',
            'log_file': 'ariba_waf',
            'max_bytes': 10 * 1024 * 1024,  # 10MB
            'backup_count': 5,
            'log_level': LogLevel.INFO.value,
            'log_format': LogFormat.JSON.value,
            'console_logging': True,
            'file_logging': True,
            'include_system_info': True,
            'date_format': '%Y-%m-%d %H:%M:%S.%f',
            'log_rotation_interval': 'D',  # Daily rotation
            'log_rotation_at': 'midnight',  # Rotate at midnight
            'log_rotation_encoding': 'utf-8'
        }

        # Merge with provided config
        self.config = {**self.default_config, **(config or {})}

        # Validate configuration
        self._validate_config()

        # Initialize logging system
        self.logger = None
        self.handlers = []
        self.lock = threading.Lock()
        self.request_counter = 0
        self.log_file_path = None

        # Initialize the logging system
        self._initialize_logging()

        # Log system startup
        self.log_system_event("Logging module initialized", LogLevel.INFO)

    def _validate_config(self):
        """Validate the configuration parameters"""
        try:
            # Validate log level
            valid_levels = [level.value for level in LogLevel]
            if self.config['log_level'] not in valid_levels:
                raise ValueError(f"Invalid log level: {self.config['log_level']}. Must be one of: {valid_levels}")

            # Validate log format
            valid_formats = [fmt.value for fmt in LogFormat]
            if self.config['log_format'] not in valid_formats:
                raise ValueError(f"Invalid log format: {self.config['log_format']}. Must be one of: {valid_formats}")

            # Validate rotation interval
            valid_intervals = ['S', 'M', 'H', 'D', 'W0', 'W1', 'W2', 'W3', 'W4', 'W5', 'W6', 'midnight']
            if self.config['log_rotation_interval'] not in valid_intervals:
                raise ValueError(f"Invalid rotation interval: {self.config['log_rotation_interval']}. Must be one of: {valid_intervals}")

            # Validate backup count
            if not isinstance(self.config['backup_count'], int) or self.config['backup_count'] < 1:
                raise ValueError("backup_count must be a positive integer")

            # Validate max bytes
            if not isinstance(self.config['max_bytes'], int) or self.config['max_bytes'] < 1024:
                raise ValueError("max_bytes must be at least 1024 bytes")

            # Create log directory if it doesn't exist
            if not os.path.exists(self.config['log_dir']):
                os.makedirs(self.config['log_dir'], exist_ok=True)

        except Exception as e:
            raise ValueError(f"Configuration validation failed: {str(e)}")

    def _initialize_logging(self):
        """Initialize the logging system with configured handlers"""
        try:
            # Create logger
            self.logger = logging.getLogger('AribaWAF')
            self.logger.setLevel(self._get_logging_level())

            # Clear any existing handlers
            for handler in self.logger.handlers[:]:
                self.logger.removeHandler(handler)
                handler.close()

            # Add console handler if enabled
            if self.config['console_logging']:
                console_handler = self._create_console_handler()
                self.handlers.append(console_handler)
                self.logger.addHandler(console_handler)

            # Add file handler if enabled
            if self.config['file_logging']:
                file_handler = self._create_file_handler()
                self.handlers.append(file_handler)
                self.logger.addHandler(file_handler)

            # Set the log file path
            self.log_file_path = os.path.join(
                self.config['log_dir'],
                f"{self.config['log_file']}.log"
            )

        except Exception as e:
            raise RuntimeError(f"Failed to initialize logging: {str(e)}")

    def _get_logging_level(self):
        """Convert log level string to logging module constant"""
        level_mapping = {
            LogLevel.DEBUG.value: logging.DEBUG,
            LogLevel.INFO.value: logging.INFO,
            LogLevel.WARNING.value: logging.WARNING,
            LogLevel.ERROR.value: logging.ERROR,
            LogLevel.CRITICAL.value: logging.CRITICAL
        }
        return level_mapping.get(self.config['log_level'], logging.INFO)

    def _create_console_handler(self):
        """Create a console handler with appropriate formatting"""
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self._get_logging_level())

        formatter = self._create_formatter()
        console_handler.setFormatter(formatter)

        return console_handler

    def _create_file_handler(self):
        """Create a file handler with rotation support"""
        # Create log directory if it doesn't exist
        os.makedirs(self.config['log_dir'], exist_ok=True)

        # Determine the appropriate handler based on rotation settings
        if self.config['log_rotation_interval'] == 'midnight':
            file_handler = logging.handlers.TimedRotatingFileHandler(
                filename=os.path.join(self.config['log_dir'], f"{self.config['log_file']}.log"),
                when=self.config['log_rotation_interval'],
                interval=1,
                backupCount=self.config['backup_count'],
                encoding=self.config['log_rotation_encoding']
            )
        else:
            file_handler = logging.handlers.RotatingFileHandler(
                filename=os.path.join(self.config['log_dir'], f"{self.config['log_file']}.log"),
                maxBytes=self.config['max_bytes'],
                backupCount=self.config['backup_count'],
                encoding=self.config['log_rotation_encoding']
            )

        file_handler.setLevel(self._get_logging_level())
        formatter = self._create_formatter()
        file_handler.setFormatter(formatter)

        return file_handler

    def _create_formatter(self):
        """Create a formatter based on the configured log format"""
        if self.config['log_format'] == LogFormat.JSON.value:
            return JSONFormatter(config=self.config)
        elif self.config['log_format'] == LogFormat.CSV.value:
            return CSVFormatter(config=self.config)
        else:  # TEXT format
            return TextFormatter(config=self.config)

    def update_config(self, new_config: Dict[str, Any]):
        """
        Update the logging configuration

        Args:
            new_config: Dictionary with new configuration values
        """
        with self.lock:
            # Update configuration
            self.config.update(new_config)

            # Re-validate configuration
            self._validate_config()

            # Re-initialize logging with new configuration
            self._initialize_logging()

            # Log configuration update
            self.log_system_event("Logging configuration updated", LogLevel.INFO)

    def log_request(self,
                   request_data: Dict[str, Any],
                   waf_action: str,
                   security_results: Optional[Dict[str, Any]] = None,
                   response_data: Optional[Dict[str, Any]] = None) -> str:
        """
        Log a complete request with all details

        Args:
            request_data: Dictionary containing request information
            waf_action: WAF action taken (allow, block, challenge)
            security_results: Security inspection results
            response_data: Response data

        Returns:
            str: Request ID for tracking
        """
        try:
            with self.lock:
                # Generate request ID
                request_id = self._generate_request_id()

                # Prepare log data
                log_data = self._prepare_request_log_data(
                    request_data, waf_action, security_results, response_data, request_id
                )

                # Log based on WAF action
                if waf_action == 'block':
                    self._log_with_level(log_data, LogLevel.WARNING)
                elif waf_action == 'challenge':
                    self._log_with_level(log_data, LogLevel.WARNING)
                else:  # allow or other actions
                    self._log_with_level(log_data, LogLevel.INFO)

                return request_id

        except Exception as e:
            error_msg = f"Failed to log request: {str(e)}"
            self._log_error(error_msg)
            return "error_" + str(int(time.time()))

    def _generate_request_id(self) -> str:
        """Generate a unique request ID"""
        with self.lock:
            self.request_counter += 1
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            counter_str = str(self.request_counter).zfill(6)
            return f"req_{timestamp}_{counter_str}"

    def _prepare_request_log_data(self,
                                request_data: Dict[str, Any],
                                waf_action: str,
                                security_results: Optional[Dict[str, Any]],
                                response_data: Optional[Dict[str, Any]],
                                request_id: str) -> Dict[str, Any]:
        """
        Prepare complete log data for a request

        Args:
            request_data: Request data
            waf_action: WAF action
            security_results: Security results
            response_data: Response data
            request_id: Generated request ID

        Returns:
            Dictionary with complete log data
        """
        # Basic request information
        log_data = {
            'timestamp': datetime.now().strftime(self.config['date_format']),
            'request_id': request_id,
            'waf_action': waf_action,
            'remote_ip': request_data.get('remote_ip', 'unknown'),
            'method': request_data.get('method', 'unknown'),
            'uri': request_data.get('uri', 'unknown'),
            'path': request_data.get('path', 'unknown'),
            'protocol': request_data.get('protocol', 'unknown'),
            'host': request_data.get('host', 'unknown'),
            'user_agent': request_data.get('headers', {}).get('User-Agent', 'unknown'),
            'content_type': request_data.get('headers', {}).get('Content-Type', 'unknown'),
            'content_length': len(request_data.get('body', '')) if isinstance(request_data.get('body'), str) else 0,
            'query_parameters': request_data.get('query_arguments', {}),
            'headers': self._sanitize_headers(request_data.get('headers', {})),
            'body': self._sanitize_body(request_data.get('body', '')),
            'security_results': security_results or {},
            'response_data': response_data or {}
        }

        # Add system information if enabled
        if self.config['include_system_info']:
            log_data['system_info'] = self._get_system_info()

        return log_data

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Sanitize headers for logging (remove sensitive data)"""
        sanitized = {}
        sensitive_headers = ['authorization', 'cookie', 'proxy-authorization', 'x-api-key']

        for key, value in headers.items():
            lower_key = key.lower()
            if lower_key in sensitive_headers:
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = str(value)

        return sanitized

    def _sanitize_body(self, body: Union[str, bytes, Dict, None]) -> str:
        """Sanitize request body for logging"""
        if body is None:
            return ""

        if isinstance(body, bytes):
            try:
                body = body.decode('utf-8', errors='replace')
            except Exception:
                body = str(body)

        if isinstance(body, dict):
            try:
                # Remove sensitive fields from JSON body
                sensitive_fields = ['password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'credit_card', 'ssn']
                sanitized_body = {}
                for key, value in body.items():
                    if key.lower() in sensitive_fields:
                        sanitized_body[key] = "***REDACTED***"
                    else:
                        sanitized_body[key] = str(value)
                return json.dumps(sanitized_body)
            except Exception:
                return "***BODY_PARSING_ERROR***"

        # For string bodies, check if it looks like JSON and sanitize if so
        if isinstance(body, str) and body.strip().startswith('{') and body.strip().endswith('}'):
            try:
                parsed = json.loads(body)
                return self._sanitize_body(parsed)
            except Exception:
                pass

        # For non-JSON string bodies, just return as-is (with length limit)
        max_body_length = 1000  # Limit body size in logs
        if len(body) > max_body_length:
            return body[:max_body_length] + f"... (truncated, original length: {len(body)})"
        return body

    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for logging"""
        return {
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'platform_version': platform.version(),
            'python_version': platform.python_version(),
            'waf_version': '1.0.0'  # This would come from a version file in production
        }

    def _log_with_level(self, log_data: Dict[str, Any], level: LogLevel):
        """Log data with the specified log level"""
        try:
            if level == LogLevel.DEBUG:
                self.logger.debug(self._format_log_message(log_data))
            elif level == LogLevel.INFO:
                self.logger.info(self._format_log_message(log_data))
            elif level == LogLevel.WARNING:
                self.logger.warning(self._format_log_message(log_data))
            elif level == LogLevel.ERROR:
                self.logger.error(self._format_log_message(log_data))
            elif level == LogLevel.CRITICAL:
                self.logger.critical(self._format_log_message(log_data))
        except Exception as e:
            self._log_error(f"Failed to log with level {level.value}: {str(e)}")

    def _format_log_message(self, log_data: Dict[str, Any]) -> str:
        """Format log data according to the configured format"""
        if self.config['log_format'] == LogFormat.JSON.value:
            return json.dumps(log_data, ensure_ascii=False, indent=2)
        elif self.config['log_format'] == LogFormat.CSV.value:
            # For CSV format, we'll create a flattened version
            flat_data = self._flatten_dict(log_data)
            return ",".join(str(value) for value in flat_data.values())
        else:  # TEXT format
            return self._format_text_log(log_data)

    def _flatten_dict(self, data: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
        """Flatten nested dictionary for CSV output"""
        flat = {}
        for key, value in data.items():
            full_key = f"{prefix}{key}" if not prefix else f"{prefix}_{key}"

            if isinstance(value, dict):
                flat.update(self._flatten_dict(value, full_key))
            elif isinstance(value, (list, tuple)):
                flat[full_key] = json.dumps(value)
            else:
                flat[full_key] = str(value)

        return flat

    def _format_text_log(self, log_data: Dict[str, Any]) -> str:
        """Format log data as plain text"""
        lines = []

        # Basic request info
        lines.append(f"[{log_data['timestamp']}] {log_data['request_id']} {log_data['waf_action'].upper()} "
                   f"{log_data['remote_ip']} {log_data['method']} {log_data['uri']}")

        # Security info if available
        if log_data.get('security_results'):
            threats = log_data['security_results'].get('threats_detected', [])
            risk_score = log_data['security_results'].get('risk_score', 0)
            if threats:
                lines.append(f"  THREATS: {', '.join(threats)} | RISK: {risk_score}")

        # Response info if available
        if log_data.get('response_data'):
            status = log_data['response_data'].get('status_code', 'N/A')
            lines.append(f"  RESPONSE: {status}")

        return "\n".join(lines)

    def log_system_event(self, message: str, level: LogLevel = LogLevel.INFO):
        """
        Log a system event

        Args:
            message: Event message
            level: Log level
        """
        try:
            log_data = {
                'timestamp': datetime.now().strftime(self.config['date_format']),
                'event_type': 'system',
                'message': message,
                'level': level.value
            }

            if self.config['include_system_info']:
                log_data['system_info'] = self._get_system_info()

            self._log_with_level(log_data, level)

        except Exception as e:
            self._log_error(f"Failed to log system event: {str(e)}")

    def log_error(self, error_message: str, exception: Optional[Exception] = None):
        """
        Log an error with optional exception details

        Args:
            error_message: Error message
            exception: Exception object (optional)
        """
        try:
            log_data = {
                'timestamp': datetime.now().strftime(self.config['date_format']),
                'event_type': 'error',
                'message': error_message,
                'level': LogLevel.ERROR.value
            }

            if exception:
                log_data['exception_type'] = type(exception).__name__
                log_data['exception_message'] = str(exception)
                log_data['stack_trace'] = traceback.format_exc()

            if self.config['include_system_info']:
                log_data['system_info'] = self._get_system_info()

            self._log_with_level(log_data, LogLevel.ERROR)

        except Exception as e:
            # Fallback to basic error logging if something goes wrong
            print(f"CRITICAL LOGGING ERROR: {str(e)}")
            print(f"Original error was: {error_message}")

    def _log_error(self, error_message: str):
        """Internal error logging that bypasses the main logging system"""
        try:
            timestamp = datetime.now().strftime(self.config['date_format'])
            error_log = f"[{timestamp}] [CRITICAL] [LOGGING_ERROR] {error_message}"

            # Try to write to a separate error log file
            error_log_path = os.path.join(self.config['log_dir'], 'logging_errors.log')
            with open(error_log_path, 'a', encoding='utf-8') as f:
                f.write(error_log + '\n')

            # Also print to console as fallback
            print(error_log)

        except Exception:
            # Ultimate fallback - just print to console
            print(f"LOGGING SYSTEM FAILURE: {error_message}")

    def get_log_file_path(self) -> str:
        """
        Get the current log file path

        Returns:
            str: Path to the current log file
        """
        return self.log_file_path or ""

    def get_log_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the logging system

        Returns:
            Dictionary with logging statistics
        """
        stats = {
            'log_level': self.config['log_level'],
            'log_format': self.config['log_format'],
            'log_file': self.get_log_file_path(),
            'handlers': len(self.handlers),
            'requests_logged': self.request_counter,
            'console_logging_enabled': self.config['console_logging'],
            'file_logging_enabled': self.config['file_logging']
        }

        # Add file size if file logging is enabled
        if self.config['file_logging'] and self.log_file_path and os.path.exists(self.log_file_path):
            stats['current_log_size'] = os.path.getsize(self.log_file_path)

        return stats

    def close(self):
        """Close the logging system and clean up resources"""
        try:
            # Remove all handlers
            for handler in self.handlers:
                if handler in self.logger.handlers:
                    self.logger.removeHandler(handler)
                    handler.close()

            self.handlers = []
            self.logger = None

            self.log_system_event("Logging module closed", LogLevel.INFO)

        except Exception as e:
            self._log_error(f"Error closing logging system: {str(e)}")

class JSONFormatter(logging.Formatter):
    """Custom formatter for JSON log format"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.config = config

    def format(self, record):
        """Format log record as JSON"""
        # Get the creation time and format it properly
        created = datetime.fromtimestamp(record.created)
        formatted_time = created.strftime(self.config['date_format'])

        log_data = {
            'timestamp': formatted_time,
            'level': record.levelname,
            'message': record.getMessage(),
            'logger': record.name
        }

        # Add exception info if available
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        # Add extra attributes
        if hasattr(record, 'request_data'):
            log_data['request_data'] = record.request_data

        return json.dumps(log_data, ensure_ascii=False)

class TextFormatter(logging.Formatter):
    """Custom formatter for text log format"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.config = config
        self.default_format = '%(asctime)s [%(levelname)s] %(message)s'

    def format(self, record):
        """Format log record as text"""
        # Use default text formatting
        formatter = logging.Formatter(self.default_format, datefmt=self.config['date_format'])
        return formatter.format(record)

class CSVFormatter(logging.Formatter):
    """Custom formatter for CSV log format"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.config = config

    def format(self, record):
        """Format log record as CSV"""
        # Get the creation time and format it properly
        created = datetime.fromtimestamp(record.created)
        formatted_time = created.strftime(self.config['date_format'])

        # For CSV, we'll use a simple format that can be parsed later
        log_data = {
            'timestamp': formatted_time,
            'level': record.levelname,
            'message': record.getMessage().replace('"', '""'),  # Escape quotes for CSV
            'logger': record.name
        }

        # Convert to CSV line
        return f'"{log_data["timestamp"]}","{log_data["level"]}","{log_data["message"]}","{log_data["logger"]}"'

# Example usage and integration
if __name__ == "__main__":
    # Example configuration
    config = {
        'log_dir': 'logs',
        'log_file': 'test_waf',
        'log_level': LogLevel.DEBUG.value,
        'log_format': LogFormat.JSON.value,
        'console_logging': True,
        'file_logging': True
    }

    # Create logging module
    logger = LoggingModule(config)

    # Example request data
    request_data = {
        'method': 'POST',
        'uri': '/api/login',
        'remote_ip': '192.168.1.100',
        'headers': {
            'User-Agent': 'Mozilla/5.0',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer token123'
        },
        'body': {
            'username': 'testuser',
            'password': 'secret123'
        }
    }

    # Example security results
    security_results = {
        'threats_detected': ['SQL_INJECTION'],
        'risk_score': 85,
        'action': 'block'
    }

    # Log a request
    request_id = logger.log_request(
        request_data=request_data,
        waf_action='block',
        security_results=security_results
    )

    print(f"Logged request with ID: {request_id}")

    # Log a system event
    logger.log_system_event("Test system event", LogLevel.INFO)

    # Get logging stats
    stats = logger.get_log_stats()
    print(f"Logging stats: {stats}")

    # Close the logger
    logger.close()