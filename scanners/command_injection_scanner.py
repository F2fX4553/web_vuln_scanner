#!/usr/bin/env python3
"""
Command Injection Scanner Module for Web Vulnerability Scanner
"""

import re
import time
import random
from urllib.parse import urlparse, parse_qs, urlencode

class CommandInjectionScanner:
    def __init__(self, scanner):
        """Initialize the Command Injection Scanner"""
        self.scanner = scanner
        self.logger = scanner.logger
        self.session = scanner.session
        self.timeout = scanner.timeout
        self.safe_mode = getattr(scanner.args, 'safe_mode', False)
    
    def check_command_injection(self, url):
        """Check for command injection vulnerabilities in a URL"""
        self.logger.debug(f"Checking for command injection vulnerabilities on {url}")
        
        # Parse the URL to extract parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Look for parameters that might be vulnerable to command injection
        for param_name, param_values in query_params.items():
            for param_value in param_values:
                self._test_command_injection_parameter(url, param_name, param_value)
    
    def check_form_command_injection(self, form_data):
        """Check for command injection vulnerabilities in a form"""
        url = form_data['url']
        action = form_data['action']
        method = form_data['method']
        inputs = form_data['inputs']
        
        self.logger.debug(f"Checking for command injection vulnerabilities in form on {url}")
        
        # Look for input fields that might be vulnerable to command injection
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_type = input_field.get('type', '')
            
            # Skip file inputs and hidden fields
            if input_type in ['file', 'hidden']:
                continue
            
            self._test_form_command_injection(url, action, method, input_name)
    
    def _test_command_injection_parameter(self, url, param_name, param_value):
        """Test a parameter for command injection vulnerability"""
        if self.safe_mode:
            # In safe mode, just report the potential vulnerability
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="Command Injection",
                description=f"Potential command injection vulnerability in parameter '{param_name}'",
                severity="MEDIUM",
                details={
                    "parameter": param_name,
                    "value": param_value,
                    "remediation": "Avoid using system commands with user input. If necessary, use allowlists and strict input validation."
                }
            )
            return
        
        # Command injection payloads to test
        payloads = self._get_command_injection_payloads()
        
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for payload in payloads:
            # Create a modified URL with the test payload
            modified_params = query_params.copy()
            modified_params[param_name] = [f"{param_value}{payload}"]
            
            # Rebuild the query string
            modified_query = urlencode(modified_params, doseq=True)
            
            # Rebuild the URL
            modified_url = parsed_url._replace(query=modified_query).geturl()
            
            try:
                # Send the request
                start_time = time.time()
                response = self.session.get(modified_url, timeout=self.timeout)
                response_time = time.time() - start_time
                
                # Check for signs of successful command injection
                if self._check_command_injection_response(response, payload, response_time):
                    self.scanner.report_vulnerability(
                        url=url,
                        vuln_type="Command Injection",
                        description=f"Command injection vulnerability in parameter '{param_name}'",
                        severity="HIGH",
                        details={
                            "parameter": param_name,
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_time": response_time,
                            "response_length": len(response.text),
                            "remediation": "Avoid using system commands with user input. If necessary, use allowlists and strict input validation."
                        }
                    )
                    # Stop testing after finding a vulnerability
                    break
            
            except Exception as e:
                self.logger.debug(f"Error testing command injection payload on {url}: {e}")
    
    def _test_form_command_injection(self, url, action, method, input_name):
        """Test a form input for command injection vulnerability"""
        if self.safe_mode:
            # In safe mode, just report the potential vulnerability
            self.scanner.report_vulnerability(
                url=url,
                vuln_type="Command Injection",
                description=f"Potential command injection vulnerability in form input '{input_name}'",
                severity="MEDIUM",
                details={
                    "form_action": action,
                    "form_method": method,
                    "input_name": input_name,
                    "remediation": "Avoid using system commands with user input. If necessary, use allowlists and strict input validation."
                }
            )
            return
        
        # Command injection payloads to test
        payloads = self._get_command_injection_payloads()
        
        for payload in payloads:
            try:
                # Prepare the form data
                form_data = {input_name: payload}
                
                # Send the request
                start_time = time.time()
                if method.upper() == 'GET':
                    response = self.session.get(action, params=form_data, timeout=self.timeout)
                else:  # POST
                    response = self.session.post(action, data=form_data, timeout=self.timeout)
                response_time = time.time() - start_time
                
                # Check for signs of successful command injection
                if self._check_command_injection_response(response, payload, response_time):
                    self.scanner.report_vulnerability(
                        url=url,
                        vuln_type="Command Injection",
                        description=f"Command injection vulnerability in form input '{input_name}'",
                        severity="HIGH",
                        details={
                            "form_action": action,
                            "form_method": method,
                            "input_name": input_name,
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_time": response_time,
                            "response_length": len(response.text),
                            "remediation": "Avoid using system commands with user input. If necessary, use allowlists and strict input validation."
                        }
                    )
                    # Stop testing after finding a vulnerability
                    break
            
            except Exception as e:
                self.logger.debug(f"Error testing command injection payload on form {action}: {e}")
    
    def _get_command_injection_payloads(self):
        """Get a list of command injection payloads to test"""
        # Basic payloads
        basic_payloads = [
            "; ping -n 5 127.0.0.1",
            "& ping -n 5 127.0.0.1",
            "| ping -n 5 127.0.0.1",
            "|| ping -n 5 127.0.0.1",
            "& ping -n 5 127.0.0.1 #",
            "; ping -n 5 127.0.0.1 #",
            "| ping -n 5 127.0.0.1 #",
            "|| ping -n 5 127.0.0.1 #",
            "` ping -n 5 127.0.0.1 `",
            "$(`ping -n 5 127.0.0.1`)",
            "; timeout 5",
            "& timeout 5",
            "| timeout 5",
            "|| timeout 5"
        ]
        
        # Obfuscated payloads
        obfuscated_payloads = [
            "%0a ping -n 5 127.0.0.1 %0a",
            "`ping -n 5 127.0.0.1`",
            "$(ping -n 5 127.0.0.1)",
            ";+ping+-n+5+127.0.0.1",
            "%7C+ping+-n+5+127.0.0.1"
        ]
        
        # Blind payloads (time-based)
        blind_payloads = [
            "; ping -n 10 127.0.0.1",
            "& ping -n 10 127.0.0.1",
            "| ping -n 10 127.0.0.1",
            "|| ping -n 10 127.0.0.1",
            "; timeout 10",
            "& timeout 10",
            "| timeout 10",
            "|| timeout 10"
        ]
        
        # Combine all payloads
        all_payloads = basic_payloads + obfuscated_payloads + blind_payloads
        
        # Shuffle to avoid detection patterns
        random.shuffle(all_payloads)
        
        return all_payloads
    
    def _check_command_injection_response(self, response, payload, response_time):
        """Check if the response indicates a successful command injection attack"""
        # Look for signs of successful command injection
        
        # Check for command output in response
        command_output_patterns = [
            r"bytes=\d+\s+time=\d+ms",  # ping output
            r"TTL=\d+",  # ping output
            r"icmp_seq=\d+",  # ping output
            r"64 bytes from",  # ping output
            r"rtt min/avg/max",  # ping output
            r"(\d+) packets transmitted, (\d+) received",  # ping output
            r"uid=\d+\(\w+\) gid=\d+\(\w+\)",  # id command output
            r"([a-zA-Z0-9_-]+):x:(\d+):(\d+):",  # /etc/passwd content
            r"root:.*:0:0:",  # /etc/passwd content
            r"Directory of",  # Windows dir command
            r"Volume in drive",  # Windows dir command
            r"Volume Serial Number",  # Windows dir command
            r"<DIR>",  # Windows dir command
            r"File\(s\)",  # Windows dir command
            r"Dir\(s\)",  # Windows dir command
            r"bytes free",  # Windows dir command
            r"bytes total",  # Windows dir command
            r"Windows (\w+) \[Version .+\]",  # Windows version
            r"Microsoft Windows \[Version .+\]",  # Windows version
            r"Linux \S+ \d+\.\d+\.\d+",  # Linux kernel version
            r"MINGW\d+",  # MinGW environment
            r"GNU/Linux"  # Linux OS
        ]
        
        for pattern in command_output_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        # Check for time-based injection
        if "ping -n 10" in payload or "timeout 10" in payload:
            if response_time > 9.5:  # Allow for some network delay
                return True
        elif "ping -n 5" in payload or "timeout 5" in payload:
            if response_time > 4.5:  # Allow for some network delay
                return True
        
        # Check for error messages that might indicate command injection
        error_patterns = [
            r"syntax error",
            r"command not found",
            r"not recognized as an internal or external command",
            r"cannot find the path specified",
            r"not recognized as a cmdlet",
            r"bad command or file name",
            r"system cannot find the path specified",
            r"system cannot find the file specified",
            r"unknown command",
            r"permission denied",
            r"operation not permitted",
            r"illegal option",
            r"invalid command",
            r"unexpected token",
            r"unexpected end of file",
            r"unexpected EOF",
            r"unterminated quoted string"
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        return False