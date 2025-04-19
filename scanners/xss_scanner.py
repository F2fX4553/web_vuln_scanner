#!/usr/bin/env python3
"""
XSS Scanner module for the Web Vulnerability Scanner
"""

import re
import random
import string
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse

class XSSScanner:
    def __init__(self, scanner):
        """Initialize the XSS scanner"""
        self.scanner = scanner
        self.payloads = self.load_payloads()
        self.reflection_markers = {}
        
    def load_payloads(self):
        """Load XSS payloads from file"""
        payloads = []
        try:
            with open('payloads/xss_payloads.txt', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except FileNotFoundError:
            # Default payloads if file not found
            payloads = [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '"><script>alert(1)</script>',
                '\'><script>alert(1)</script>'
            ]
        
        return payloads
    
    def generate_marker(self):
        """Generate a unique marker for tracking payload reflections"""
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    
    def check_xss(self, url, response):
        """Check for XSS vulnerabilities"""
        self.scanner.logger.info(f"Checking for XSS vulnerabilities on {url}")
        
        # Check for potential XSS in HTML response
        self._check_passive_xss(url, response)
        
        # Extract forms for active testing
        forms = self._extract_forms(url, response.text)
        
        # Test each form
        for form in forms:
            self._test_form(url, form)
        
        # Test URL parameters
        self._test_url_parameters(url)
    
    def _check_passive_xss(self, url, response):
        """Check for potential XSS indicators without active testing"""
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for dangerous JS patterns
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Check for patterns that might indicate DOM XSS
                if re.search(r'document\.URL|document\.documentURI|location\.href|location\.search|location\.hash', script.string):
                    self.scanner.report_vulnerability(
                        url,
                        "Potential DOM XSS",
                        "JavaScript code uses location or document properties that could lead to DOM-based XSS",
                        "MEDIUM",
                        {"evidence": script.string[:200] + "..." if len(script.string) > 200 else script.string}
                    )
        
        # Check for input fields without proper encoding/validation attributes
        inputs = soup.find_all('input')
        for input_field in inputs:
            if input_field.get('type') in ['text', 'search', 'url', 'email', 'tel', None]:
                if not any(attr in input_field.attrs for attr in ['pattern', 'maxlength']):
                    self.scanner.report_vulnerability(
                        url,
                        "Potential XSS Vector",
                        "Page contains elements that could be vulnerable to XSS if user input is reflected",
                        "LOW",
                        {}
                    )
                    break
    
    def _extract_forms(self, base_url, html):
        """Extract forms from HTML content"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            # Convert relative URL to absolute URL
            action_url = urljoin(base_url, action) if action else base_url
            
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name', '')
                input_value = input_tag.get('value', '')
                
                # Skip submit buttons and hidden fields for XSS testing
                if input_type not in ['submit', 'button', 'image', 'reset', 'file']:
                    inputs.append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })
            
            forms.append({
                'action': action_url,
                'method': method,
                'inputs': inputs
            })
        
        return forms
    
    def _test_form(self, url, form):
        """Test a form for XSS vulnerabilities"""
        self.scanner.logger.debug(f"Testing form on {url} with action {form['action']}")
        
        # For each input in the form
        for input_field in form['inputs']:
            if not input_field['name']:
                continue
                
            # For each payload
            for payload in self.payloads:
                # Create a unique marker for this test
                marker = self.generate_marker()
                marked_payload = f"{marker}{payload}{marker}"
                
                # Prepare the data to submit
                data = {}
                for inp in form['inputs']:
                    if inp['name'] == input_field['name']:
                        data[inp['name']] = marked_payload
                    elif inp['name']:
                        # Use original value or a generic value
                        data[inp['name']] = inp['value'] if inp['value'] else 'test'
                
                try:
                    # Submit the form
                    if form['method'] == 'post':
                        response = self.scanner.session.post(
                            form['action'],
                            data=data,
                            timeout=self.scanner.timeout,
                            allow_redirects=True
                        )
                    else:
                        response = self.scanner.session.get(
                            form['action'],
                            params=data,
                            timeout=self.scanner.timeout,
                            allow_redirects=True
                        )
                    
                    # Check if the payload is reflected in the response
                    if marker in response.text:
                        # Check if the payload is executed (not just reflected)
                        if self._check_payload_execution(response.text, marker, payload):
                            self.scanner.report_vulnerability(
                                url,
                                "XSS Vulnerability",
                                f"XSS payload executed via {form['method'].upper()} parameter '{input_field['name']}'",
                                "HIGH",
                                {
                                    "form_action": form['action'],
                                    "form_method": form['method'],
                                    "vulnerable_parameter": input_field['name'],
                                    "payload": payload
                                }
                            )
                            return  # Found a vulnerability, no need to test more payloads
                        else:
                            self.scanner.report_vulnerability(
                                url,
                                "Reflected XSS Potential",
                                f"XSS payload reflected but not executed via {form['method'].upper()} parameter '{input_field['name']}'",
                                "MEDIUM",
                                {
                                    "form_action": form['action'],
                                    "form_method": form['method'],
                                    "vulnerable_parameter": input_field['name'],
                                    "payload": payload
                                }
                            )
                
                except requests.exceptions.RequestException as e:
                    self.scanner.logger.error(f"Error testing form on {url}: {e}")
    
    def _test_url_parameters(self, url):
        """Test URL parameters for XSS vulnerabilities"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            return
        
        self.scanner.logger.debug(f"Testing URL parameters on {url}")
        
        # For each parameter in the URL
        for param_name, param_values in params.items():
            # For each payload
            for payload in self.payloads:
                # Create a unique marker for this test
                marker = self.generate_marker()
                marked_payload = f"{marker}{payload}{marker}"
                
                # Prepare the parameters
                test_params = params.copy()
                test_params[param_name] = [marked_payload]
                
                try:
                    # Build the test URL
                    test_url = url.split('?')[0] + '?' + '&'.join([
                        f"{p}={v[0]}" for p, v in test_params.items()
                    ])
                    
                    # Send the request
                    response = self.scanner.session.get(
                        test_url,
                        timeout=self.scanner.timeout,
                        allow_redirects=True
                    )
                    
                    # Check if the payload is reflected in the response
                    if marker in response.text:
                        # Check if the payload is executed (not just reflected)
                        if self._check_payload_execution(response.text, marker, payload):
                            self.scanner.report_vulnerability(
                                url,
                                "XSS Vulnerability",
                                f"XSS payload executed via URL parameter '{param_name}'",
                                "HIGH",
                                {
                                    "vulnerable_parameter": param_name,
                                    "payload": payload
                                }
                            )
                            return  # Found a vulnerability, no need to test more payloads
                        else:
                            self.scanner.report_vulnerability(
                                url,
                                "Reflected XSS Potential",
                                f"XSS payload reflected but not executed via URL parameter '{param_name}'",
                                "MEDIUM",
                                {
                                    "vulnerable_parameter": param_name,
                                    "payload": payload
                                }
                            )
                
                except requests.exceptions.RequestException as e:
                    self.scanner.logger.error(f"Error testing URL parameter on {url}: {e}")
    
    def _check_payload_execution(self, html, marker, payload):
        """
        Check if the payload is executed (not just reflected)
        This is a heuristic approach and may not be 100% accurate
        """
        # If the marker is in the HTML but the full marked payload is not,
        # it might indicate that the payload was executed
        if marker in html and f"{marker}{payload}{marker}" not in html:
            # Additional checks for specific payloads
            if '<script>' in payload:
                # Check if the script tags were removed but the marker remains
                return True
            elif 'onerror=' in payload or 'onload=' in payload:
                # Check if the event handler was triggered
                return True
        
        return False