#!/usr/bin/env python3
"""
CSRF Scanner Module for Web Vulnerability Scanner
"""

from bs4 import BeautifulSoup
import re

class CSRFScanner:
    def __init__(self, scanner):
        """Initialize the CSRF Scanner"""
        self.scanner = scanner
        self.logger = scanner.logger
        self.session = scanner.session
        self.timeout = scanner.timeout
    
    def check_csrf(self, url, response):
        """Check for CSRF vulnerabilities in a page"""
        # Look for forms in the page
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            # Skip forms with GET method as they are not vulnerable to CSRF
            method = form.get('method', 'get').lower()
            if method != 'post':
                continue
            
            # Check if the form has a CSRF token
            has_csrf_token = False
            
            # Look for common CSRF token field names
            csrf_field_names = [
                'csrf', 'xsrf', 'token', '_token', 'authenticity_token',
                'csrf_token', 'xsrf_token', 'security_token'
            ]
            
            for input_field in form.find_all('input'):
                field_name = input_field.get('name', '').lower()
                field_value = input_field.get('value', '')
                
                # Check if any of the common CSRF token field names are present
                if any(token_name in field_name for token_name in csrf_field_names):
                    has_csrf_token = True
                    break
            
            # If no CSRF token is found, check for other security measures
            if not has_csrf_token:
                # Check for custom headers in JavaScript that might be used for CSRF protection
                scripts = soup.find_all('script')
                has_custom_header = False
                
                for script in scripts:
                    if script.string and re.search(r'X-CSRF|X-Requested-With|X-XSRF', script.string):
                        has_custom_header = True
                        break
                
                if not has_custom_header:
                    # Form is potentially vulnerable to CSRF
                    form_action = form.get('action', '')
                    form_id = form.get('id', 'unknown')
                    
                    # Report the vulnerability
                    self.scanner.report_vulnerability(
                        url=url,
                        vuln_type="CSRF",
                        description=f"Form with ID '{form_id}' and action '{form_action}' does not have CSRF protection",
                        severity="MEDIUM",
                        details={
                            "form_id": form_id,
                            "form_action": form_action,
                            "remediation": "Implement CSRF tokens in all forms that perform state-changing actions"
                        }
                    )
    
    def check_form_csrf(self, form_data):
        """Check a specific form for CSRF vulnerabilities"""
        url = form_data['url']
        action = form_data['action']
        method = form_data['method']
        
        # Skip forms with GET method as they are not vulnerable to CSRF
        if method != 'POST':
            return
        
        # Check if the form has a CSRF token
        has_csrf_token = False
        
        # Look for common CSRF token field names
        csrf_field_names = [
            'csrf', 'xsrf', 'token', '_token', 'authenticity_token',
            'csrf_token', 'xsrf_token', 'security_token'
        ]
        
        for input_field in form_data['inputs']:
            field_name = input_field.get('name', '').lower()
            
            # Check if any of the common CSRF token field names are present
            if any(token_name in field_name for token_name in csrf_field_names):
                has_csrf_token = True
                break
        
        if not has_csrf_token:
            # Form is potentially vulnerable to CSRF
            form_id = "unknown"
            
            # Report the vulnerability
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="CSRF",
                description=f"Form with action '{action}' does not have CSRF protection",
                severity="MEDIUM",
                details={
                    "form_action": action,
                    "remediation": "Implement CSRF tokens in all forms that perform state-changing actions"
                }
            )