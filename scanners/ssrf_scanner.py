#!/usr/bin/env python3
"""
SSRF Scanner Module for Web Vulnerability Scanner
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse, parse_qs, urljoin

class SSRFScanner:
    def __init__(self, scanner):
        """Initialize the SSRF Scanner"""
        self.scanner = scanner
        self.logger = scanner.logger
        self.session = scanner.session
        self.timeout = scanner.timeout
        self.safe_mode = scanner.args.safe_mode
    
    def check_ssrf(self, url):
        """Check for SSRF vulnerabilities in a URL"""
        # Parse the URL to extract parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Look for parameters that might be vulnerable to SSRF
        for param_name, param_values in query_params.items():
            # Check if parameter name suggests it might be used for URL operations
            if self._is_potential_ssrf_param(param_name):
                for param_value in param_values:
                    # Check if parameter value looks like a URL or IP address
                    if self._is_url_or_ip(param_value):
                        self._test_ssrf_parameter(url, param_name, param_value)
    
    def check_form_ssrf(self, form_data):
        """Check for SSRF vulnerabilities in a form"""
        url = form_data['url']
        action = form_data['action']
        method = form_data['method']
        inputs = form_data['inputs']
        
        # Look for input fields that might be vulnerable to SSRF
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_type = input_field.get('type', '')
            
            # Check if input name suggests it might be used for URL operations
            if self._is_potential_ssrf_param(input_name):
                self._test_ssrf_form_input(url, action, method, input_name)
    
    def _is_potential_ssrf_param(self, param_name):
        """Check if parameter name suggests it might be used for URL operations"""
        ssrf_keywords = [
            'url', 'uri', 'link', 'src', 'source', 'dest', 'destination',
            'redirect', 'return', 'site', 'html', 'path', 'continue', 'window',
            'next', 'data', 'reference', 'ref', 'feed', 'host', 'port', 'file',
            'document', 'domain', 'callback', 'return', 'page', 'view', 'api',
            'proxy', 'target'
        ]
        
        param_lower = param_name.lower()
        return any(keyword in param_lower for keyword in ssrf_keywords)
    
    def _is_url_or_ip(self, value):
        """Check if a value looks like a URL or IP address"""
        # Check if it's a URL
        if value.startswith(('http://', 'https://', '//', 'ftp://')):
            return True
        
        # Check if it's an IP address
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            pass
        
        # Check if it might be a hostname
        if '.' in value and not ' ' in value:
            try:
                socket.gethostbyname(value)
                return True
            except:
                pass
        
        return False
    
    def _test_ssrf_parameter(self, url, param_name, param_value):
        """Test a parameter for SSRF vulnerability"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if self.safe_mode:
            # In safe mode, just report the potential vulnerability
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="SSRF",
                description=f"Potential SSRF vulnerability in parameter '{param_name}'",
                severity="MEDIUM",
                details={
                    "parameter": param_name,
                    "value": param_value,
                    "remediation": "Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains and IP ranges."
                }
            )
            return
        
        # Test with internal IP addresses
        test_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://169.254.169.254",  # AWS metadata service
            "http://192.168.0.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "file:///etc/passwd",
            "file:///C:/Windows/win.ini"
        ]
        
        for payload in test_payloads:
            # Create a modified URL with the test payload
            modified_params = query_params.copy()
            modified_params[param_name] = [payload]
            
            # Rebuild the query string
            from urllib.parse import urlencode
            modified_query = urlencode(modified_params, doseq=True)
            
            # Rebuild the URL
            modified_url = parsed_url._replace(query=modified_query).geturl()
            
            try:
                # Send the request
                response = self.session.get(modified_url, timeout=self.timeout, allow_redirects=False)
                
                # Check for signs of successful SSRF
                if self._check_ssrf_response(response, payload):
                    self.scanner.report_vulnerability(
                        url=url,
                        vuln_type="SSRF",
                        description=f"SSRF vulnerability in parameter '{param_name}'",
                        severity="HIGH",
                        details={
                            "parameter": param_name,
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_length": len(response.text),
                            "remediation": "Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains and IP ranges."
                        }
                    )
                    # Stop testing after finding a vulnerability
                    break
            
            except Exception as e:
                self.logger.debug(f"Error testing SSRF payload {payload} on {url}: {e}")
    
    def _test_ssrf_form_input(self, url, action, method, input_name):
        """Test a form input for SSRF vulnerability"""
        if self.safe_mode:
            # In safe mode, just report the potential vulnerability
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="SSRF",
                description=f"Potential SSRF vulnerability in form input '{input_name}'",
                severity="MEDIUM",
                details={
                    "form_action": action,
                    "form_method": method,
                    "input_name": input_name,
                    "remediation": "Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains and IP ranges."
                }
            )
            return
        
        # Test with internal IP addresses
        test_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://169.254.169.254",  # AWS metadata service
            "http://192.168.0.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "file:///etc/passwd",
            "file:///C:/Windows/win.ini"
        ]
        
        for payload in test_payloads:
            try:
                # Prepare the form data
                form_data = {input_name: payload}
                
                # Send the request
                if method == 'GET':
                    response = self.session.get(action, params=form_data, timeout=self.timeout, allow_redirects=False)
                else:  # POST
                    response = self.session.post(action, data=form_data, timeout=self.timeout, allow_redirects=False)
                
                # Check for signs of successful SSRF
                if self._check_ssrf_response(response, payload):
                    self.scanner.report_vulnerability(
                        url=url,
                        vuln_type="SSRF",
                        description=f"SSRF vulnerability in form input '{input_name}'",
                        severity="HIGH",
                        details={
                            "form_action": action,
                            "form_method": method,
                            "input_name": input_name,
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_length": len(response.text),
                            "remediation": "Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains and IP ranges."
                        }
                    )
                    # Stop testing after finding a vulnerability
                    break
            
            except Exception as e:
                self.logger.debug(f"Error testing SSRF payload {payload} on form {action}: {e}")
    
    def _check_ssrf_response(self, response, payload):
        """Check if the response indicates a successful SSRF attack"""
        # Look for signs of successful SSRF
        
        # Check for specific content based on the payload
        if "127.0.0.1" in payload or "localhost" in payload:
            # Look for signs of a web server response
            if "<html" in response.text.lower() or "<body" in response.text.lower():
                return True
        
        elif "169.254.169.254" in payload:
            # Look for AWS metadata
            if "ami-id" in response.text or "instance-id" in response.text:
                return True
        
        elif "file://" in payload:
            # Look for file content
            if "/etc/passwd" in payload and ("root:" in response.text or "nobody:" in response.text):
                return True
            elif "win.ini" in payload and ("[fonts]" in response.text or "[extensions]" in response.text):
                return True
        
        # Check for unusual response codes that might indicate successful SSRF
        if response.status_code in [200, 301, 302] and len(response.text) > 0:
            # This is a heuristic and might lead to false positives
            return True
        
        return False