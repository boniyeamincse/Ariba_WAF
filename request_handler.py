import json
import tornado.web
from typing import Dict, Any, Optional

class AribaRequestHandler(tornado.web.RequestHandler):
    """
    Request Handler module for Ariba WAF that intercepts HTTP requests,
    extracts request data, and prepares it for security inspection.
    """

    def initialize(self, security_engine=None):
        """
        Initialize the handler with a security engine reference.

        Args:
            security_engine: Reference to the security inspection engine
        """
        self.security_engine = security_engine

    def prepare(self):
        """
        Prepare the request for processing by extracting and parsing data.
        This method is called before any HTTP method handlers.
        """
        # Extract basic request information
        self.request_data = {
            'method': self.request.method,
            'uri': self.request.uri,
            'path': self.request.path,
            'headers': dict(self.request.headers),
            'remote_ip': self.request.remote_ip,
            'protocol': self.request.protocol,
            'host': self.request.host,
            'body': None,
            'query_arguments': dict(self.request.query_arguments),
            'cookies': self.request.cookies
        }

        # Parse request body based on content type
        self._parse_request_body()

        # Log the request for debugging purposes
        self._log_request()

    def _parse_request_body(self):
        """
        Parse the request body based on content type.
        """
        content_type = self.request.headers.get('Content-Type', '')

        try:
            if 'application/json' in content_type:
                if self.request.body:
                    self.request_data['body'] = json.loads(self.request.body.decode('utf-8'))
                else:
                    self.request_data['body'] = {}
            elif 'application/x-www-form-urlencoded' in content_type:
                if self.request.body:
                    body_str = self.request.body.decode('utf-8')
                    self.request_data['body'] = {}
                    for pair in body_str.split('&'):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            self.request_data['body'][key] = value
                else:
                    self.request_data['body'] = {}
            elif 'multipart/form-data' in content_type:
                # For multipart data, we'll store the raw body
                self.request_data['body'] = self.request.body
            else:
                # For other content types, store as text
                if self.request.body:
                    self.request_data['body'] = self.request.body.decode('utf-8')
                else:
                    self.request_data['body'] = ''
        except Exception as e:
            self.request_data['body'] = None
            self.request_data['body_parse_error'] = str(e)

    def _log_request(self):
        """
        Log request details for debugging and monitoring purposes.
        """
        # In a real implementation, this would log to a proper logging system
        print(f"Request received: {self.request.method} {self.request.uri}")
        print(f"From: {self.request.remote_ip}")
        print(f"Headers: {list(self.request.headers.keys())}")

    def send_to_security_engine(self) -> Dict[str, Any]:
        """
        Send the prepared request data to the security engine for inspection.

        Returns:
            Dictionary containing security inspection results
        """
        if not self.security_engine:
            return {
                'status': 'warning',
                'message': 'No security engine configured',
                'request_data': self.request_data,
                'security_results': {
                    'threats_detected': [],
                    'risk_score': 0,
                    'action': 'allow'
                }
            }

        try:
            # Send data to security engine for inspection
            security_results = self.security_engine.inspect(self.request_data)

            return {
                'status': 'success',
                'message': 'Request processed by security engine',
                'request_data': self.request_data,
                'security_results': security_results
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Security engine error: {str(e)}',
                'request_data': self.request_data,
                'security_results': {
                    'threats_detected': [],
                    'risk_score': 0,
                    'action': 'allow'  # Default to allow if security engine fails
                }
            }

    def handle_response(self, security_results: Dict[str, Any]) -> None:
        """
        Handle the response based on security inspection results.

        Args:
            security_results: Dictionary containing security inspection results
        """
        if security_results['security_results']['action'] == 'block':
            self._respond_with_block(security_results)
        elif security_results['security_results']['action'] == 'challenge':
            self._respond_with_challenge(security_results)
        else:
            # Default action is allow
            self._respond_with_allow(security_results)

    def _respond_with_block(self, security_results: Dict[str, Any]) -> None:
        """
        Respond with a block response when security threats are detected.

        Args:
            security_results: Security inspection results
        """
        self.set_status(403)
        response = {
            'status': 'blocked',
            'message': 'Request blocked by security policy',
            'threats_detected': security_results['security_results']['threats_detected'],
            'risk_score': security_results['security_results']['risk_score'],
            'request_id': security_results.get('request_id', 'unknown')
        }
        self.write(response)
        self.finish()

    def _respond_with_challenge(self, security_results: Dict[str, Any]) -> None:
        """
        Respond with a challenge when additional verification is needed.

        Args:
            security_results: Security inspection results
        """
        self.set_status(401)
        response = {
            'status': 'challenge',
            'message': 'Additional verification required',
            'challenge_type': security_results['security_results'].get('challenge_type', 'captcha'),
            'threats_detected': security_results['security_results']['threats_detected'],
            'risk_score': security_results['security_results']['risk_score'],
            'request_id': security_results.get('request_id', 'unknown')
        }
        self.write(response)
        self.finish()

    def _respond_with_allow(self, security_results: Dict[str, Any]) -> None:
        """
        Respond normally when request is allowed.

        Args:
            security_results: Security inspection results
        """
        # For allowed requests, we can add security headers
        self.set_header('X-Ariba-WAF', 'Processed')
        self.set_header('X-Request-ID', security_results.get('request_id', 'unknown'))

        # In a real implementation, this would forward the request to the actual application
        # For this basic structure, we'll just return a success response
        response = {
            'status': 'allowed',
            'message': 'Request processed successfully',
            'security_results': {
                'threats_detected': security_results['security_results']['threats_detected'],
                'risk_score': security_results['security_results']['risk_score']
            }
        }
        self.write(response)
        self.finish()

    def get(self):
        """
        Handle GET requests.
        """
        security_results = self.send_to_security_engine()
        self.handle_response(security_results)

    def post(self):
        """
        Handle POST requests.
        """
        security_results = self.send_to_security_engine()
        self.handle_response(security_results)

    def put(self):
        """
        Handle PUT requests.
        """
        security_results = self.send_to_security_engine()
        self.handle_response(security_results)

    def delete(self):
        """
        Handle DELETE requests.
        """
        security_results = self.send_to_security_engine()
        self.handle_response(security_results)

    def head(self):
        """
        Handle HEAD requests.
        """
        security_results = self.send_to_security_engine()
        self.handle_response(security_results)

    def options(self):
        """
        Handle OPTIONS requests.
        """
        security_results = self.send_to_security_engine()
        self.handle_response(security_results)

    def patch(self):
        """
        Handle PATCH requests.
        """
        security_results = self.send_to_security_engine()
        self.handle_response(security_results)