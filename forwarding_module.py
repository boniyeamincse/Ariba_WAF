import json
import logging
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urljoin
import tornado.httpclient
import tornado.gen
import tornado.ioloop
from tornado.httpclient import HTTPRequest, HTTPResponse, HTTPError
from tornado.httputil import HTTPHeaders
try:
    from tornado.httpclient import HTTPTimeoutError
except ImportError:
    # For older tornado versions
    HTTPTimeoutError = tornado.iostream.StreamClosedError

class ForwardingModule:
    """
    Forwarding module for Ariba WAF that forwards allowed requests to backend servers.

    Features:
    - Async HTTP client using Tornado's AsyncHTTPClient
    - Support for multiple HTTP methods (GET, POST, PUT, DELETE, etc.)
    - Preserves original request headers and body
    - Configurable backend server URLs
    - Error handling and retry mechanism
    - Response handling and forwarding
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the ForwardingModule.

        Args:
            config: Configuration dictionary containing:
                - backend_url: Base URL of the backend server
                - max_retries: Maximum number of retry attempts (default: 3)
                - timeout: Request timeout in seconds (default: 30)
                - retry_delay: Delay between retries in seconds (default: 1)
                - allowed_methods: List of allowed HTTP methods (default: all)
        """
        self.config = config or {}
        self.backend_url = self.config.get('backend_url', 'http://localhost:8080')
        self.max_retries = self.config.get('max_retries', 3)
        self.timeout = self.config.get('timeout', 30)
        self.retry_delay = self.config.get('retry_delay', 1)
        self.allowed_methods = self.config.get('allowed_methods', ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])

        # Initialize HTTP client
        self.http_client = tornado.httpclient.AsyncHTTPClient()

        # Configure logging
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)

    def update_config(self, new_config: Dict[str, Any]):
        """
        Update the module configuration.

        Args:
            new_config: New configuration dictionary
        """
        self.config.update(new_config)
        self.backend_url = self.config.get('backend_url', self.backend_url)
        self.max_retries = self.config.get('max_retries', self.max_retries)
        self.timeout = self.config.get('timeout', self.timeout)
        self.retry_delay = self.config.get('retry_delay', self.retry_delay)
        self.allowed_methods = self.config.get('allowed_methods', self.allowed_methods)

    async def forward_request(self, method: str, path: str, headers: Dict[str, str],
                            body: Optional[bytes] = None) -> Tuple[int, Dict[str, str], bytes]:
        """
        Forward an HTTP request to the backend server.

        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            path: Request path (will be joined with backend_url)
            headers: Request headers dictionary
            body: Request body as bytes

        Returns:
            Tuple of (status_code, response_headers, response_body)

        Raises:
            HTTPError: If request fails after all retry attempts
            ValueError: If method is not allowed
        """
        if method.upper() not in self.allowed_methods:
            raise ValueError(f"Method {method} not allowed. Allowed methods: {', '.join(self.allowed_methods)}")

        # Construct full URL
        full_url = urljoin(self.backend_url, path)

        # Create HTTP request
        request = self._create_http_request(method, full_url, headers, body)

        # Execute with retry logic
        return await self._execute_with_retry(request)

    def _create_http_request(self, method: str, url: str, headers: Dict[str, str],
                           body: Optional[bytes]) -> HTTPRequest:
        """
        Create an HTTPRequest object from the given parameters.

        Args:
            method: HTTP method
            url: Full URL
            headers: Request headers
            body: Request body

        Returns:
            HTTPRequest object
        """
        # Convert headers to HTTPHeaders object
        http_headers = HTTPHeaders()

        # Filter and add headers (exclude hop-by-hop headers)
        for header_name, header_value in headers.items():
            if header_name.lower() not in ['host', 'connection', 'keep-alive', 'proxy-authenticate',
                                         'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade']:
                http_headers.add(header_name, header_value)

        # Add X-Forwarded-For header if not present
        if 'X-Forwarded-For' not in http_headers:
            http_headers.add('X-Forwarded-For', 'Ariba-WAF')

        return HTTPRequest(
            url=url,
            method=method,
            headers=http_headers,
            body=body,
            connect_timeout=self.timeout,
            request_timeout=self.timeout,
            follow_redirects=False,
            allow_nonstandard_methods=True
        )

    async def _execute_with_retry(self, request: HTTPRequest) -> Tuple[int, Dict[str, str], bytes]:
        """
        Execute HTTP request with retry logic.

        Args:
            request: HTTPRequest object

        Returns:
            Tuple of (status_code, response_headers, response_body)

        Raises:
            HTTPError: If request fails after all retry attempts
        """
        last_error = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = await self.http_client.fetch(request)
                return self._process_response(response)
            except (HTTPError, tornado.iostream.StreamClosedError, ConnectionError) as e:
                last_error = e
                self.logger.warning(f"Attempt {attempt} failed: {str(e)}")

                if attempt < self.max_retries:
                    self.logger.info(f"Retrying in {self.retry_delay} seconds...")
                    await tornado.gen.sleep(self.retry_delay)
                else:
                    self.logger.error(f"All {self.max_retries} attempts failed")
                    break

        # If we get here, all retries failed
        if last_error:
            raise last_error
        else:
            raise HTTPError(500, "Unknown error occurred during request forwarding")

    def _process_response(self, response: HTTPResponse) -> Tuple[int, Dict[str, str], bytes]:
        """
        Process the HTTP response and extract relevant information.

        Args:
            response: HTTPResponse object

        Returns:
            Tuple of (status_code, response_headers, response_body)
        """
        # Convert headers to dictionary
        response_headers = {}
        for header_name, header_value in response.headers.get_all():
            response_headers[header_name] = header_value

        # Get response body
        response_body = response.body

        self.logger.info(f"Backend response: {response.code} {response.reason}")

        return response.code, response_headers, response_body

    async def close(self):
        """Close the HTTP client."""
        self.http_client.close()

    # Convenience methods for common HTTP methods
    async def forward_get(self, path: str, headers: Dict[str, str]) -> Tuple[int, Dict[str, str], bytes]:
        """Forward GET request."""
        return await self.forward_request('GET', path, headers)

    async def forward_post(self, path: str, headers: Dict[str, str],
                          body: Optional[bytes] = None) -> Tuple[int, Dict[str, str], bytes]:
        """Forward POST request."""
        return await self.forward_request('POST', path, headers, body)

    async def forward_put(self, path: str, headers: Dict[str, str],
                         body: Optional[bytes] = None) -> Tuple[int, Dict[str, str], bytes]:
        """Forward PUT request."""
        return await self.forward_request('PUT', path, headers, body)

    async def forward_delete(self, path: str, headers: Dict[str, str]) -> Tuple[int, Dict[str, str], bytes]:
        """Forward DELETE request."""
        return await self.forward_request('DELETE', path, headers)

    async def forward_patch(self, path: str, headers: Dict[str, str],
                           body: Optional[bytes] = None) -> Tuple[int, Dict[str, str], bytes]:
        """Forward PATCH request."""
        return await self.forward_request('PATCH', path, headers, body)

    async def forward_head(self, path: str, headers: Dict[str, str]) -> Tuple[int, Dict[str, str], bytes]:
        """Forward HEAD request."""
        return await self.forward_request('HEAD', path, headers)

    async def forward_options(self, path: str, headers: Dict[str, str]) -> Tuple[int, Dict[str, str], bytes]:
        """Forward OPTIONS request."""
        return await self.forward_request('OPTIONS', path, headers)