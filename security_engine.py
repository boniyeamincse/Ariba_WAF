import re
from typing import Dict, Any, Tuple, Optional

class SecurityEngine:
    """
    Basic Security Engine for Ariba WAF
    Implements regex-based detection for SQL Injection and XSS attacks
    """

    def __init__(self, sensitivity: str = "medium"):
        """
        Initialize Security Engine with configurable sensitivity

        Args:
            sensitivity: Sensitivity level ('low', 'medium', 'high')
        """
        self.sensitivity = sensitivity.lower()
        self._validate_sensitivity()

        # SQL Injection patterns with different sensitivity levels
        self.sqli_patterns = {
            'low': [
                r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|UNION|OR\s+1=1)\b',
                r'\b(SELECT\s+\*.*FROM|INSERT\s+INTO.*VALUES)\b',
                r'\b(EXEC\s+sp_|xp_)\b'
            ],
            'medium': [
                r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|UNION|OR\s+1=1|--|#|\/\*|\*\/)\b',
                r'\b(SELECT\s+\*.*FROM|INSERT\s+INTO.*VALUES|UPDATE.*SET)\b',
                r'\b(EXEC\s+sp_|xp_|WAITFOR\s+DELAY)\b',
                r'\b(OR\s+[0-9]+=[0-9]+|AND\s+[0-9]+=[0-9]+)\b',
                r'\b(BENCHMARK|SLEEP|LOAD_FILE)\b'
            ],
            'high': [
                r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|UNION|OR\s+1=1|--|#|\/\*|\*\/|;|\\x)\b',
                r'\b(SELECT\s+\*.*FROM|INSERT\s+INTO.*VALUES|UPDATE.*SET|DELETE.*FROM)\b',
                r'\b(EXEC\s+sp_|xp_|WAITFOR\s+DELAY|DECLARE\s+@)\b',
                r'\b(OR\s+[0-9]+=[0-9]+|AND\s+[0-9]+=[0-9]+|LIKE\s+0x)\b',
                r'\b(BENCHMARK|SLEEP|LOAD_FILE|INTO\s+OUTFILE|DUMPFILE)\b',
                r'\b(CHAR\s*\(\s*[0-9]+\s*\)|CONCAT\s*\(\s*.*\s*\))\b',
                r'\b(0x[0-9a-fA-F]+)\b'
            ]
        }

        # XSS patterns with different sensitivity levels
        self.xss_patterns = {
            'low': [
                r'<script[^>]*>.*?</script>',
                r'on\w+\s*=',
                r'javascript:',
                r'eval\s*\('
            ],
            'medium': [
                r'<script[^>]*>.*?</script>',
                r'on\w+\s*=',
                r'javascript:',
                r'eval\s*\(',
                r'<[^>]+>',
                r'<script>',
                r'&#x3c;script&#x3e;',
                r'document\.cookie',
                r'window\.location',
                r'alert\s*\('
            ],
            'high': [
                r'<script[^>]*>.*?</script>',
                r'on\w+\s*=',
                r'javascript:',
                r'eval\s*\(',
                r'<[^>]+>',
                r'<script>',
                r'&#x3c;script&#x3e;',
                r'document\.cookie',
                r'window\.location',
                r'alert\s*\(',
                r'<img[^>]+src[^>]*>',
                r'<iframe[^>]*>',
                r'<meta[^>]+http-equiv[^>]*>',
                r'<link[^>]+rel[^>]*>',
                r'<object[^>]*>',
                r'<embed[^>]*>',
                r'<applet[^>]*>',
                r'<form[^>]+action[^>]*>',
                r'vbscript:',
                r'expression\s*\(',
                r'&#[0-9]+;',
                r'&#x[0-9a-fA-F]+;'
            ]
        }

    def _validate_sensitivity(self):
        """Validate sensitivity level"""
        valid_levels = ['low', 'medium', 'high']
        if self.sensitivity not in valid_levels:
            raise ValueError(f"Invalid sensitivity level. Must be one of: {valid_levels}")

    def _compile_patterns(self, pattern_list: list) -> re.Pattern:
        """Compile multiple patterns into a single regex pattern"""
        if not pattern_list:
            return None
        combined_pattern = '|'.join(pattern_list)
        return re.compile(combined_pattern, re.IGNORECASE)

    def detect_sqli(self, input_data: str) -> Tuple[bool, Optional[list]]:
        """
        Detect SQL Injection patterns in input data

        Args:
            input_data: String to analyze for SQLi patterns

        Returns:
            Tuple of (is_malicious, matches)
        """
        if not input_data or not isinstance(input_data, str):
            return False, None

        patterns = self.sqli_patterns.get(self.sensitivity, [])
        compiled_pattern = self._compile_patterns(patterns)

        if compiled_pattern:
            matches = compiled_pattern.findall(input_data)
            return (len(matches) > 0, matches)

        return False, None

    def detect_xss(self, input_data: str) -> Tuple[bool, Optional[list]]:
        """
        Detect XSS patterns in input data

        Args:
            input_data: String to analyze for XSS patterns

        Returns:
            Tuple of (is_malicious, matches)
        """
        if not input_data or not isinstance(input_data, str):
            return False, None

        patterns = self.xss_patterns.get(self.sensitivity, [])
        compiled_pattern = self._compile_patterns(patterns)

        if compiled_pattern:
            matches = compiled_pattern.findall(input_data)
            return (len(matches) > 0, matches)

        return False, None

    def analyze_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze request for malicious content

        Args:
            request_data: Dictionary containing request data (headers, body, params, etc.)

        Returns:
            Dictionary with analysis results
        """
        if not request_data or not isinstance(request_data, dict):
            return {
                'blocked': False,
                'reason': 'Invalid request data',
                'sqli_detected': False,
                'xss_detected': False,
                'matches': {}
            }

        analysis_result = {
            'blocked': False,
            'reason': None,
            'sqli_detected': False,
            'xss_detected': False,
            'matches': {},
            'sensitivity': self.sensitivity
        }

        # Check various parts of the request
        parts_to_check = [
            'headers',
            'body',
            'params',
            'query',
            'url',
            'cookies',
            'form_data'
        ]

        for part in parts_to_check:
            if part in request_data:
                data = request_data[part]
                if isinstance(data, dict):
                    data = str(data)
                elif not isinstance(data, str):
                    data = str(data)

                # Check for SQLi
                sqli_detected, sqli_matches = self.detect_sqli(data)
                if sqli_detected:
                    analysis_result['sqli_detected'] = True
                    analysis_result['matches']['sqli'] = analysis_result['matches'].get('sqli', []) + sqli_matches

                # Check for XSS
                xss_detected, xss_matches = self.detect_xss(data)
                if xss_detected:
                    analysis_result['xss_detected'] = True
                    analysis_result['matches']['xss'] = analysis_result['matches'].get('xss', []) + xss_matches

        # Decision making
        if analysis_result['sqli_detected'] or analysis_result['xss_detected']:
            analysis_result['blocked'] = True
            reasons = []
            if analysis_result['sqli_detected']:
                reasons.append('SQL Injection patterns detected')
            if analysis_result['xss_detected']:
                reasons.append('XSS patterns detected')
            analysis_result['reason'] = '; '.join(reasons)

        return analysis_result

    def set_sensitivity(self, sensitivity: str):
        """Set sensitivity level"""
        self.sensitivity = sensitivity.lower()
        self._validate_sensitivity()

    def get_sensitivity(self) -> str:
        """Get current sensitivity level"""
        return self.sensitivity