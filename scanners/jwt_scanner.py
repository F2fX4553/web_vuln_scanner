#!/usr/bin/env python3
"""
JWT Scanner Module for Web Vulnerability Scanner
"""

import re
import json
import base64
import hmac
import hashlib
from urllib.parse import urlparse, parse_qs

class JWTScanner:
    def __init__(self, scanner):
        """Initialize the JWT Scanner"""
        self.scanner = scanner
        self.logger = scanner.logger
        self.session = scanner.session
        self.timeout = scanner.timeout
        self.safe_mode = getattr(scanner.args, 'safe_mode', False)
        
        # Common JWT secrets for testing
        self.common_secrets = [
            "",  # Empty secret
            "secret",
            "jwt_secret",
            "jwt-secret",
            "auth_secret",
            "auth-secret",
            "api_secret",
            "api-secret",
            "secret_key",
            "secret-key",
            "private_key",
            "private-key",
            "app_secret",
            "app-secret",
            "token_secret",
            "token-secret",
            "your_secret",
            "your-secret",
            "supersecret",
            "super-secret",
            "mysecret",
            "my-secret",
            "password",
            "1234567890",
            "qwertyuiop",
            "123456789",
            "12345678",
            "1234567",
            "123456",
            "12345"
        ]
    
    def check_jwt(self, url, response=None):
        """Check for JWT vulnerabilities in a URL"""
        self.logger.debug(f"Checking for JWT vulnerabilities on {url}")
        
        # Extract JWT tokens from URL parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param_name, param_values in query_params.items():
            for param_value in param_values:
                if self._is_jwt(param_value):
                    self._analyze_jwt(url, param_name, param_value)
        
        # If response is provided, check headers and cookies
        if response:
            self.check_headers_for_jwt(url, response.headers)
            self.check_cookies_for_jwt(url, response.cookies)
    
    def check_headers_for_jwt(self, url, headers):
        """Check for JWT vulnerabilities in response headers"""
        for header_name, header_value in headers.items():
            if self._is_jwt(header_value):
                self._analyze_jwt(url, f"Header: {header_name}", header_value)
    
    def check_cookies_for_jwt(self, url, cookies):
        """Check for JWT vulnerabilities in cookies"""
        for cookie_name, cookie_value in cookies.items():
            if self._is_jwt(cookie_value):
                self._analyze_jwt(url, f"Cookie: {cookie_name}", cookie_value)
    
    def _is_jwt(self, token):
        """Check if a string is a JWT token"""
        jwt_pattern = r'^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*$'
        return bool(re.match(jwt_pattern, token))
    
    def _analyze_jwt(self, url, location, token):
        """Analyze a JWT token for vulnerabilities"""
        self.logger.debug(f"Analyzing JWT token in {location} on {url}")
        
        try:
            # Split the token into its parts
            header_b64, payload_b64, signature_b64 = token.split('.')
            
            # Decode the header and payload
            header_json = self._decode_base64(header_b64)
            payload_json = self._decode_base64(payload_b64)
            
            # Parse the JSON
            header = json.loads(header_json)
            payload = json.loads(payload_json)
            
            # Check for vulnerabilities
            self._check_none_algorithm(url, location, token, header, payload)
            self._check_weak_algorithm(url, location, token, header, payload)
            self._check_missing_signature(url, location, token, header, payload, signature_b64)
            self._check_key_confusion(url, location, token, header, payload)
            self._check_expiration(url, location, token, header, payload)
            self._check_sensitive_data(url, location, token, header, payload)
            
            # If not in safe mode, try to brute force the secret
            if not self.safe_mode:
                self._brute_force_secret(url, location, token, header, payload)
        
        except Exception as e:
            self.logger.debug(f"Error analyzing JWT token: {e}")
    
    def _decode_base64(self, data):
        """Decode base64url to string"""
        # Add padding if needed
        padded = data + '=' * (4 - len(data) % 4) if len(data) % 4 else data
        # Replace URL-safe characters
        padded = padded.replace('-', '+').replace('_', '/')
        # Decode
        return base64.b64decode(padded).decode('utf-8')
    
    def _check_none_algorithm(self, url, location, token, header, payload):
        """Check for 'none' algorithm vulnerability"""
        if header.get('alg', '').lower() == 'none':
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="JWT None Algorithm",
                description=f"JWT token in {location} uses 'none' algorithm",
                severity="HIGH",
                details={
                    "location": location,
                    "token": token,
                    "header": header,
                    "payload": payload,
                    "remediation": "Reject tokens with 'none' algorithm. Always validate the algorithm and signature."
                }
            )
        else:
            # Test for 'none' algorithm acceptance
            if not self.safe_mode:
                # Create a new token with 'none' algorithm
                new_header = header.copy()
                new_header['alg'] = 'none'
                
                # Encode the new header
                new_header_b64 = base64.b64encode(json.dumps(new_header).encode()).decode('utf-8')
                new_header_b64 = new_header_b64.replace('+', '-').replace('/', '_').rstrip('=')
                
                # Create the new token (with empty signature)
                payload_b64 = token.split('.')[1]
                new_token = f"{new_header_b64}.{payload_b64}."
                
                # Test if the server accepts this token
                # This would require additional implementation to test the token against the server
    
    def _check_weak_algorithm(self, url, location, token, header, payload):
        """Check for weak algorithm vulnerability"""
        weak_algorithms = ['HS256', 'HS384', 'HS512']  # HMAC algorithms with shared secrets
        
        if header.get('alg', '') in weak_algorithms:
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="JWT Weak Algorithm",
                description=f"JWT token in {location} uses potentially weak algorithm {header.get('alg')}",
                severity="MEDIUM",
                details={
                    "location": location,
                    "token": token,
                    "algorithm": header.get('alg'),
                    "remediation": "Consider using stronger algorithms like RS256, ES256, or EdDSA. Ensure secrets are sufficiently long and complex."
                }
            )
    
    def _check_missing_signature(self, url, location, token, header, payload, signature_b64):
        """Check for missing signature vulnerability"""
        if not signature_b64:
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="JWT Missing Signature",
                description=f"JWT token in {location} has no signature",
                severity="HIGH",
                details={
                    "location": location,
                    "token": token,
                    "remediation": "Always sign JWT tokens and validate signatures on the server."
                }
            )
    
    def _check_key_confusion(self, url, location, token, header, payload):
        """Check for key confusion vulnerability"""
        if header.get('alg', '').startswith('HS') and 'kid' in header:
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="JWT Key Confusion",
                description=f"JWT token in {location} may be vulnerable to key confusion attacks",
                severity="MEDIUM",
                details={
                    "location": location,
                    "token": token,
                    "algorithm": header.get('alg'),
                    "kid": header.get('kid'),
                    "remediation": "Validate the 'kid' parameter and ensure it points to the correct key. Use separate keys for different algorithms."
                }
            )
    
    def _check_expiration(self, url, location, token, header, payload):
        """Check for missing or far-future expiration"""
        import time
        
        current_time = int(time.time())
        exp_time = payload.get('exp')
        
        if not exp_time:
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="JWT No Expiration",
                description=f"JWT token in {location} has no expiration time",
                severity="MEDIUM",
                details={
                    "location": location,
                    "token": token,
                    "payload": payload,
                    "remediation": "Always include an expiration time (exp) in JWT tokens."
                }
            )
        elif exp_time > current_time + 31536000:  # More than a year in the future
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="JWT Long Expiration",
                description=f"JWT token in {location} has a very long expiration time",
                severity="LOW",
                details={
                    "location": location,
                    "token": token,
                    "expiration": exp_time,
                    "current_time": current_time,
                    "difference_days": (exp_time - current_time) // 86400,
                    "remediation": "Use shorter expiration times for JWT tokens."
                }
            )
    
    def _check_sensitive_data(self, url, location, token, header, payload):
        """Check for sensitive data in the payload"""
        sensitive_keys = [
            'password', 'passwd', 'secret', 'api_key', 'apikey', 'api-key',
            'access_key', 'accesskey', 'access-key', 'private_key', 'privatekey',
            'private-key', 'secret_key', 'secretkey', 'secret-key', 'token',
            'ssn', 'social', 'credit_card', 'creditcard', 'credit-card', 'card',
            'cvv', 'cvc', 'pin'
        ]
        
        found_sensitive = []
        for key in payload:
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                found_sensitive.append(key)
        
        if found_sensitive:
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="JWT Sensitive Data",
                description=f"JWT token in {location} contains potentially sensitive data",
                severity="MEDIUM",
                details={
                    "location": location,
                    "sensitive_fields": found_sensitive,
                    "remediation": "Avoid storing sensitive data in JWT tokens. JWT tokens are easily decoded."
                }
            )
    
    def _brute_force_secret(self, url, location, token, header, payload):
        """Attempt to brute force the JWT secret"""
        if header.get('alg', '').startswith('HS'):
            header_b64, payload_b64, signature_b64 = token.split('.')
            message = f"{header_b64}.{payload_b64}".encode()
            
            for secret in self.common_secrets:
                try:
                    # Skip empty secrets if the token has a signature
                    if not secret and signature_b64:
                        continue
                    
                    # Get the correct hash function based on the algorithm
                    hash_func = {
                        'HS256': hashlib.sha256,
                        'HS384': hashlib.sha384,
                        'HS512': hashlib.sha512
                    }.get(header.get('alg'))
                    
                    if not hash_func:
                        continue
                    
                    # Calculate the signature
                    calculated_signature = hmac.new(
                        secret.encode(),
                        message,
                        hash_func
                    ).digest()
                    
                    # Encode the signature in base64url format
                    calculated_signature_b64 = base64.b64encode(calculated_signature).decode('utf-8')
                    calculated_signature_b64 = calculated_signature_b64.replace('+', '-').replace('/', '_').rstrip('=')
                    
                    # Compare with the actual signature
                    if calculated_signature_b64 == signature_b64:
                        self.scanner.report_vulnerability(
                            url=url,
                            vuln_type="JWT Weak Secret",
                            description=f"JWT token in {location} uses a weak or common secret",
                            severity="CRITICAL",
                            details={
                                "location": location,
                                "token": token,
                                "algorithm": header.get('alg'),
                                "secret": secret,
                                "remediation": "Use a strong, unique secret for JWT tokens. Consider using asymmetric algorithms like RS256."
                            }
                        )
                        return
                
                except Exception as e:
                    self.logger.debug(f"Error testing JWT secret: {e}")