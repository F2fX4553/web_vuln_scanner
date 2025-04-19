#!/usr/bin/env python3
"""
API Security Scanner module for the Web Vulnerability Scanner
"""

import re
import json
import requests
from urllib.parse import urlparse, urljoin

class APIScanner:
    def __init__(self, scanner):
        """Initialize the API Security scanner"""
        self.scanner = scanner
        self.api_endpoints = []
        self.common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3', 
            '/rest', '/graphql', '/query', '/service',
            '/services', '/app', '/mobile', '/mobile-api',
            '/json', '/jsonp', '/data', '/feed', '/feeds',
            '/ajax', '/proxy', '/swagger', '/swagger-ui',
            '/api-docs', '/openapi', '/docs'
        ]
    
    def discover_api_endpoints(self, url):
        """Discover potential API endpoints"""
        self.scanner.logger.info(f"Discovering API endpoints on {url}")
        
        # Parse the base URL
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Check common API paths
        for path in self.common_api_paths:
            api_url = urljoin(base_url, path)
            try:
                response = self.scanner.session.get(
                    api_url, 
                    timeout=self.scanner.timeout,
                    allow_redirects=True
                )
                
                # Check if the response looks like an API
                if self._is_api_response(response):
                    self.api_endpoints.append(api_url)
                    self.scanner.logger.info(f"Discovered API endpoint: {api_url}")
                    
                    # Check for API vulnerabilities
                    self.check_api_security(api_url, response)
            
            except requests.exceptions.RequestException as e:
                self.scanner.logger.error(f"Error checking API endpoint {api_url}: {e}")
    
    def _is_api_response(self, response):
        """Check if a response looks like it's from an API"""
        # Check content type
        content_type = response.headers.get('Content-Type', '')
        if 'application/json' in content_type or 'application/xml' in content_type:
            return True
        
        # Try to parse as JSON
        try:
            json_data = response.json()
            return True
        except:
            pass
        
        # Check for API-like patterns in the response
        api_patterns = [
            r'"api":', r'"data":', r'"results":', r'"status":', r'"message":',
            r'"error":', r'"errors":', r'"success":', r'"code":', r'"version":'
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, response.text):
                return True
        
        return False
    
    def check_api_security(self, url, response=None):
        """Check API security issues"""
        self.scanner.logger.info(f"Checking API security on {url}")
        
        if response is None:
            try:
                response = self.scanner.session.get(
                    url, 
                    timeout=self.scanner.timeout,
                    allow_redirects=True
                )
            except requests.exceptions.RequestException as e:
                self.scanner.logger.error(f"Error checking API security on {url}: {e}")
                return
        
        # Check for missing authentication
        self._check_missing_auth(url, response)
        
        # Check for sensitive information exposure
        self._check_sensitive_info(url, response)
        
        # Check for CORS misconfiguration
        self._check_cors_config(url)
        
        # Check for rate limiting
        self._check_rate_limiting(url)
        
        # Check for API documentation exposure
        self._check_api_docs_exposure(url)
    
    def _check_missing_auth(self, url, response):
        """Check if the API requires authentication"""
        # If we got a 200 OK response with data, try to check if it should be protected
        if response.status_code == 200:
            try:
                # Try to parse the response as JSON
                data = response.json()
                
                # Check if the response contains data that might be sensitive
                sensitive_keys = ['user', 'users', 'account', 'accounts', 'profile', 'profiles', 
                                 'customer', 'customers', 'admin', 'member', 'members', 'patient', 
                                 'patients', 'payment', 'payments', 'credit', 'transaction', 
                                 'transactions', 'order', 'orders']
                
                for key in sensitive_keys:
                    if self._find_key_in_json(data, key):
                        self.scanner.report_vulnerability(
                            url,
                            "Potential Missing API Authentication",
                            "API endpoint may return sensitive data without requiring authentication",
                            "HIGH",
                            {
                                "endpoint": url,
                                "status_code": response.status_code,
                                "sensitive_key_found": key
                            }
                        )
                        return
            except:
                pass
    
    def _find_key_in_json(self, json_data, target_key):
        """Recursively search for a key in JSON data"""
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                if key.lower() == target_key.lower():
                    return True
                if isinstance(value, (dict, list)) and self._find_key_in_json(value, target_key):
                    return True
        elif isinstance(json_data, list):
            for item in json_data:
                if isinstance(item, (dict, list)) and self._find_key_in_json(item, target_key):
                    return True
        return False
    
    def _check_sensitive_info(self, url, response):
        """Check for sensitive information exposure in API responses"""
        # Check for sensitive data patterns in the response
        sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email address'),
            (r'\b(?:\d[ -]*?){13,16}\b', 'credit card number'),
            (r'\b\d{3}[-. ]?\d{2}[-. ]?\d{4}\b', 'SSN'),
            (r'\bpassword\b|\bpasswd\b|\bsecret\b|\bapikey\b|\bapi_key\b|\btoken\b|\baccess_token\b', 'credential'),
            (r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', 'internal IP address')
        ]
        
        for pattern, data_type in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                self.scanner.report_vulnerability(
                    url,
                    "API Sensitive Information Exposure",
                    f"API response contains potential {data_type} information",
                    "HIGH",
                    {
                        "endpoint": url,
                        "data_type": data_type,
                        "matches_count": len(matches)
                    }
                )
                break
    
    def _check_cors_config(self, url):
        """Check for CORS misconfiguration"""
        try:
            # Send a request with Origin header
            headers = {'Origin': 'https://attacker.com'}
            response = self.scanner.session.options(
                url,
                headers=headers,
                timeout=self.scanner.timeout
            )
            
            # Check Access-Control-Allow-Origin header
            allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
            
            if allow_origin == '*' or allow_origin == 'https://attacker.com':
                self.scanner.report_vulnerability(
                    url,
                    "API CORS Misconfiguration",
                    f"API allows cross-origin requests from {allow_origin}",
                    "MEDIUM",
                    {
                        "endpoint": url,
                        "access_control_allow_origin": allow_origin,
                        "access_control_allow_credentials": response.headers.get('Access-Control-Allow-Credentials', '')
                    }
                )
        
        except requests.exceptions.RequestException as e:
            self.scanner.logger.error(f"Error checking CORS configuration on {url}: {e}")
    
    def _check_rate_limiting(self, url):
        """Check for rate limiting on API"""
        try:
            # Send multiple requests in quick succession
            for _ in range(10):
                response = self.scanner.session.get(
                    url,
                    timeout=self.scanner.timeout
                )
            
            # Check for rate limiting headers
            rate_limit_headers = [
                'X-Rate-Limit', 'X-RateLimit-Limit', 'X-RateLimit-Remaining',
                'X-RateLimit-Reset', 'Retry-After', 'RateLimit-Limit',
                'RateLimit-Remaining', 'RateLimit-Reset'
            ]
            
            has_rate_limiting = any(header in response.headers for header in rate_limit_headers)
            
            if not has_rate_limiting and response.status_code != 429:  # 429 Too Many Requests
                self.scanner.report_vulnerability(
                    url,
                    "API Missing Rate Limiting",
                    "API does not implement rate limiting, which could lead to abuse",
                    "MEDIUM",
                    {
                        "endpoint": url,
                        "status_code": response.status_code
                    }
                )
        
        except requests.exceptions.RequestException as e:
            self.scanner.logger.error(f"Error checking rate limiting on {url}: {e}")
    
    def _check_api_docs_exposure(self, url):
        """Check for exposed API documentation"""
        # Common API documentation paths
        doc_paths = [
            '/swagger', '/swagger-ui', '/swagger-ui.html', '/swagger/index.html',
            '/api-docs', '/api/docs', '/docs', '/documentation', '/openapi',
            '/openapi.json', '/openapi.yaml', '/spec', '/api/spec'
        ]
        
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for path in doc_paths:
            doc_url = urljoin(base_url, path)
            try:
                response = self.scanner.session.get(
                    doc_url,
                    timeout=self.scanner.timeout,
                    allow_redirects=True
                )
                
                # Check if it looks like API documentation
                if response.status_code == 200 and (
                    'swagger' in response.text.lower() or
                    'openapi' in response.text.lower() or
                    'api documentation' in response.text.lower() or
                    'api-docs' in response.text.lower()
                ):
                    self.scanner.report_vulnerability(
                        url,
                        "API Documentation Exposure",
                        f"API documentation is publicly accessible at {doc_url}",
                        "LOW",
                        {
                            "documentation_url": doc_url
                        }
                    )
                    break
            
            except requests.exceptions.RequestException as e:
                self.scanner.logger.error(f"Error checking API documentation at {doc_url}: {e}")